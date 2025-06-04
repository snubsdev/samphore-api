import json
import os
from fastapi import FastAPI, HTTPException, Request, Response, Security, Depends, Query, status
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.security.api_key import APIKeyHeader, APIKeyQuery
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from starlette.status import HTTP_403_FORBIDDEN
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Optional
from ipaddress import ip_address, ip_network # For IP range checks
import random
import httpx
import time
import asyncio
import re # <--- ADD THIS LINE


DOCS_HOST = "moose.apilogic.uk"
DATA_FILE = "quotes.json"
# app = FastAPI(docs_url=None)
app = FastAPI(title="API Logic", version="3.2c", swagger_ui_parameters={"syntaxHighlight": {"theme": "obsidian"}}, docs_url="/",redoc_url="/redoc")
app.mount("/static", StaticFiles(directory="static"), name="static")



class HostRedirectAndDocsRestrictMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        requested_host = request.url.hostname # e.g., "api.apilogic.uk", "www.apilogic.uk", "localhost"

        # 1. Handle wildcard domain redirection for the root path
        # Check if the host matches *.apilogic.uk but is NOT DOCS_HOST
        # and the request is for the root path "/"
        if (
            re.match(r"^(?!moose\.)[^.]+\.apilogic\.uk$", requested_host) # Matches *.apilogic.uk but NOT moose.apilogic.uk
            and path == "/"
        ):
            # Construct the target URL for redirection
            target_url = f"http://{DOCS_HOST}/" # Always redirect to HTTP if you're not enforcing HTTPS yet
            return RedirectResponse(url=target_url, status_code=status.HTTP_302_FOUND)

        # 2. Handle restriction of docs endpoints on non-DOCS_HOSTs
        # Define the paths that should be restricted when not on DOCS_HOST
        # This includes the root path "/" if it's the docs_url for DOCS_HOST
        restricted_doc_paths = {"/", "/redoc", "/openapi.json"}

        # Check if the path is one of the restricted doc paths AND the host is not the DOCS_HOST
        if path in restricted_doc_paths and requested_host != DOCS_HOST:
            # Return a 404 Not Found response for these doc paths on non-docs hosts
            return Response("Not Found", status_code=status.HTTP_404_NOT_FOUND)

        # 3. If neither of the above conditions were met, proceed with the request
        response = await call_next(request)
        return response


app.add_middleware(HostRedirectAndDocsRestrictMiddleware)


from fastapi.middleware.cors import CORSMiddleware

def get_client_ip_from_scope(scope, request):
    cf_ip = request.headers.get("cf-connecting-ip")
    if cf_ip:
        return cf_ip
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(',')[0].strip()
    return scope.get("client")[0] if scope.get("client") else None

class HostBasedRestrictionASGIMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)
        hostname = request.headers.get("host", "").split(":")[0].lower()
        path = request.url.path.rstrip('/')
        api_key = (
            request.headers.get("x-api-key")
            or request.query_params.get("api_key")
        )
        print("=== Incoming Request ===")
        print(f"Host: {hostname}")
        print(f"Path: {path}")
        print(f"API Key: {api_key}")
        print(f"Client IP: {get_client_ip_from_scope(scope, request)}")
        print("=======================")
        # Restrict /quotes to api.snubs.dev only
        if path == "/quotes" and hostname != "snubs.apilogic.uk":
            response = JSONResponse(
                status_code=404,
                content={"detail": "Endpoint doesn't exist on this domain"}
            )
            await response(scope, receive, send)
            return

        # Restrict /tracking and all subpaths to api.timesbus.org only
        if (path == "/tracking" or path.startswith("/tracking/")) and hostname not in ("api.timesbus.org", "tb.apilogic.uk"):
            response = JSONResponse(
                status_code=404,
                content={"detail": "Endpoint doesn't exist on this domain"}
            )
            await response(scope, receive, send)
            return

        await self.app(scope, receive, send)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # or ["*"] for all
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API_KEY = "ccb26009-3702-4273-a9a7-2e97df3759c4"  # <-- Set your key here or load from env
API_KEY_NAME = "x-app-key"
# --- API Keys Data (Example - replace with your secure storage) ---
API_KEYS_DATA = {
    "ccb26009-3702-4273-a9a7-2e97df3759c4": {"ip_restricted": False},
    "ash-dev": {"ip_restricted": False},
    "mark-dev": {"ip_restricted": False},
    "timesbus-vm": {"ip_restricted": True, "allowed_ips": ["51.38.86.12", "51.195.171.220"]},
    "b5a27c69-4e25-430d-935a-5f840b348ebf": {"ip_restricted": False},
}

# --- Security Schemes ---
API_KEY_HEADER = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_HEADER, auto_error=False)
api_key_query = APIKeyQuery(name="api_key", auto_error=False)

app.add_middleware(HostBasedRestrictionASGIMiddleware)

# --- Helper to get client IP considering proxies ---
def get_client_ip(request: Request) -> str:
    # Check X-Forwarded-For header (commonly set by proxies)
    # This assumes your proxy is trusted and setting this header correctly.
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        # The header can be a comma-separated list of IPs.
        # The client's IP is typically the first one.
        return forwarded_for.split(',')[0].strip()
    # Fallback to the direct client host
    return request.client.host

# --- API Key Dependency ---
async def get_api_key(
    request: Request,
    api_key_header: str = Security(api_key_header),
    api_key_query: str = Security(api_key_query),
):
    provided_key = api_key_header or api_key_query

    if not provided_key:
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN, detail="API KEY missing"
        )

    key_info = API_KEYS_DATA.get(provided_key)

    if not key_info:
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN, detail="Invalid API KEY"
        )

    # If the key is IP restricted, check the client's IP
    if key_info.get("ip_restricted", False):
        client_ip_str = get_client_ip(request)
        try:
            client_ip = ip_address(client_ip_str)
        except ValueError:
             raise HTTPException(status_code=403, detail="Invalid client IP format")

        allowed = False
        for allowed_ip_or_network in key_info.get("allowed_ips", []):
            try:
                # Check if the client IP is in the allowed IP or network
                if client_ip == ip_address(allowed_ip_or_network):
                    allowed = True
                    break
                network = ip_network(allowed_ip_or_network, strict=False)
                if client_ip in network:
                    allowed = True
                    break
            except ValueError:
                # Handle invalid IP or network configurations in your data
                print(f"Warning: Invalid IP or network '{allowed_ip_or_network}' in API_KEYS_DATA")
                continue

        if not allowed:
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN, detail="API KEY restricted to specific IP(s)"
            )

    # If not IP restricted, or if IP check passed, the key is valid
    return provided_key

class Quote(BaseModel):
    id: int
    author: str
    text: str
    tags: List[str] = Field(default_factory=list)
    published: bool = False

class QuoteCreate(BaseModel):
    author: str
    text: str
    tags: List[str] = Field(default_factory=list)
    published: bool = False

def load_quotes():
    if not os.path.exists(DATA_FILE):
        with open(DATA_FILE, "w") as f:
            json.dump([], f)
    with open(DATA_FILE, "r") as f:
        return json.load(f)

def save_quotes(quotes):
    with open(DATA_FILE, "w") as f:
        json.dump(quotes, f, indent=2)

def get_next_id(quotes):
    if not quotes:
        return 1
    return max(q["id"] for q in quotes) + 1

REMOTE_SVG_URL = "https://cdn.snubs.dev/favicon.svg"

@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    async with httpx.AsyncClient() as client:
        resp = await client.get(REMOTE_SVG_URL)
    if resp.status_code != 200:
        raise HTTPException(status_code=404, detail="Remote favicon not found")
    return Response(content=resp.content, media_type="image/svg+xml")

@app.get("/quotes", response_model=List[Quote])
def read_quotes(
    skip: int = 0,
    limit: int = 10,
    published: Optional[bool] = Query(None),
    tags: Optional[str] = Query(None)
):
    quotes = load_quotes()

    # Filter by published if provided
    if published is not None:
        quotes = [q for q in quotes if q.get("published", False) == published]

    # Filter by tags if provided
    if tags:
        tag_list = [t.strip().lower() for t in tags.split(",") if t.strip()]
        quotes = [
            q for q in quotes
            if any(tag.lower() in [qt.lower() for qt in q.get("tags", [])] for tag in tag_list)
        ]

    return quotes[skip : skip + limit]

@app.get("/quotes/random", response_model=Quote)
def get_random_quote(
    published: Optional[bool] = Query(None),
    tags: Optional[str] = Query(None)
):
    quotes = load_quotes()

    # Filter by published if provided
    if published is not None:
        quotes = [q for q in quotes if q.get("published", False) == published]

    # Filter by tags if provided
    if tags:
        tag_list = [t.strip().lower() for t in tags.split(",") if t.strip()]
        quotes = [
            q for q in quotes
            if any(tag.lower() in [qt.lower() for qt in q.get("tags", [])] for tag in tag_list)
        ]

    if not quotes:
        raise HTTPException(status_code=404, detail="No quotes available for the given filters")
    return random.choice(quotes)

@app.get("/quotes/{quote_id}", response_model=Quote)
def read_quote(quote_id: int):
    quotes = load_quotes()
    for q in quotes:
        if q["id"] == quote_id:
            return q
    raise HTTPException(status_code=404, detail="Quote not found")

IMAGE_FOLDER = "images"  # Change this to your folder path

@app.get("/iquote", include_in_schema=False)
def iquote():
    if os.environ.get("IQUOTE_ENABLED", "1") != "1":
        raise HTTPException(status_code=401, detail="Endpoint disabled")
    # List all files in the folder (filter for images)
    allowed_exts = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"}
    files = [
        f for f in os.listdir(IMAGE_FOLDER)
        if os.path.isfile(os.path.join(IMAGE_FOLDER, f)) and os.path.splitext(f)[1].lower() in allowed_exts
    ]
    if not files:
        raise HTTPException(status_code=404, detail="No images found")
    headers = {
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
        "Expires": "0"
    }
    chosen = random.choice(files)
    return FileResponse(
        os.path.join(IMAGE_FOLDER, chosen),
        media_type="image/" + os.path.splitext(chosen)[1][1:].lower(),
        headers=headers
    )

@app.post("/quotes", response_model=Quote)
def create_quote(quote: QuoteCreate, api_key: str = Depends(get_api_key)):
    quotes = load_quotes()
    new_id = get_next_id(quotes)
    new_quote = quote.dict()
    new_quote["id"] = new_id
    quotes.append(new_quote)
    save_quotes(quotes)
    return new_quote

@app.put("/quotes/{quote_id}", response_model=Quote)
def update_quote(quote_id: int, quote: QuoteCreate, api_key: str = Depends(get_api_key)):
    quotes = load_quotes()
    for idx, q in enumerate(quotes):
        if q["id"] == quote_id:
            updated = quote.dict()
            updated["id"] = quote_id
            quotes[idx] = updated
            save_quotes(quotes)
            return updated
    raise HTTPException(status_code=404, detail="Quote not found")

@app.delete("/quotes/{quote_id}")
def delete_quote(quote_id: int, api_key: str = Depends(get_api_key)):
    quotes = load_quotes()
    for idx, q in enumerate(quotes):
        if q["id"] == quote_id:
            del quotes[idx]
            save_quotes(quotes)
            return {"ok": True}
    raise HTTPException(status_code=404, detail="Quote not found")

@app.get("/tracking/teampennine")
async def tracking_teampennine(api_key: str = Depends(get_api_key)):
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/122.0.0.0 Safari/537.36"
        ),
        "Accept": "application/xml",
        "Referer": "https://portal.transdevbus.co.uk/",
    }
    url = (
        "https://portal.transdevbus.co.uk/api/buses/realtime"
        "?distanceUnit=km&showBusesNotInService=true&region=teampennine"
    )
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, headers=headers, timeout=15.0)
        if resp.status_code not in (200, 202):
            raise HTTPException(
                status_code=resp.status_code,
                detail=f"Upstream error: {resp.text}"
            )
        # Return the XML as-is, with correct content-type
        return Response(
            content=resp.content,
            media_type="application/xml"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching XML: {e}")

@app.get("/tracking/irishcitylink")
async def tracking_irish_citylink(api_key: str = Depends(get_api_key)):
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/122.0.0.0 Safari/537.36"
        ),
        "Accept": "application/xml",
        "Referer": "https://portal.transdevbus.co.uk/",
    }
    url = (
        "https://portal.citylink.ie/api/buses/realtime"
        "?distanceUnit=km&showBusesNotInService=true"
    )
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, headers=headers, timeout=15.0)
        if resp.status_code not in (200, 202):
            raise HTTPException(
                status_code=resp.status_code,
                detail=f"Upstream error: {resp.status_code} {resp.text}"                                                                                                                    )
        # Return the XML as-is, with correct content-type
        return Response(
            content=resp.content,
            media_type="application/xml"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching XML: {e}")

@app.get("/tracking/harrogatebus")
async def tracking_harrogatebus(api_key: str = Depends(get_api_key)):
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/122.0.0.0 Safari/537.36"
        ),
        "Accept": "application/xml",
        "Referer": "https://portal.transdevbus.co.uk/",
    }
    url = (
        "https://portal.transdevbus.co.uk/api/buses/realtime"
        "?distanceUnit=km&showBusesNotInService=true&region=harrogatebus"
    )
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(url, headers=headers, timeout=15.0)
        if resp.status_code not in (200, 202):
            raise HTTPException(
                status_code=resp.status_code,
                detail=f"Upstream error: {resp.status_code} {resp.text}"
            )
        # Return the XML as-is, with correct content-type
        return Response(
            content=resp.content,
            media_type="application/xml"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching XML: {e}")

@app.api_route(
    "/tracking/passenger/{opco}",
    methods=["GET"],
)
async def tracking_passenger(opco: str, request: Request, api_key: str = Depends(get_api_key)):
    # Build the target URL
    target_url = f"https://{opco}.arcticapi.com/network/vehicles"

    # Forward all query parameters except 'api_key'
    params = {k: v for k, v in request.query_params.items() if k.lower() != "api_key"}

    # Prepare headers (copy most, but not host)
    headers = dict(request.headers)
    headers.pop("host", None)

    # Forward the request to the target URL
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                params=params,
                content=await request.body(),
                timeout=30.0,
            )
        except httpx.RequestError as e:
            raise HTTPException(status_code=502, detail=f"Upstream error: {e}")

    # Return the proxied response
    return Response(
        content=resp.content,
        status_code=resp.status_code,
        headers={k: v for k, v in resp.headers.items() if k.lower() not in {"content-encoding", "transfer-encoding", "connection"}},
        media_type=resp.headers.get("content-type"),
    )

@app.get("/tracking/guernsey")
async def tracking_guernsey(api_key: str = Depends(get_api_key)):
    API_URL = (
        "https://ticketless-app.api.urbanthings.cloud/api/2/vehiclepositions"
        "?maxLatitude=49.515683&maxLongitude=-2.495113"
        "&minLatitude=49.434045&minLongitude=-2.660374"
    )
    HEADERS = {
        "x-api-key": "TIzVfvPTlb5bjo69rsOPbabDVhwwgSiLaV5MCiME",
        "x-ut-app": "travel.ticketless.app.guernsey;platform=web",
    }
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(API_URL, headers=HEADERS, timeout=15.0)
        if response.status_code != 200:
            error_text = response.text
            print('API Error:', response.status_code, response.reason_phrase, error_text)
            return JSONResponse(
                status_code=response.status_code,
                content={
                    "error": "Failed to fetch data from external API",
                    "details": error_text,
                },
            )
        data = response.json()
        return data
    except Exception as error:
        print('Fetch Error:', error)
        return JSONResponse(
            status_code=500,
            content={
                "error": "An internal server error occurred",
                "details": str(error),
            },
        )
@app.get("/v1/main/vehicles")
async def timesbus_vehicles(request: Request):
    API_URL = (
        "https://timesbus.org/vehicles.json"
    )
    params = dict(request.query_params)
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(API_URL, params=params, timeout=15.0)
        if response.status_code != 200:
            error_text = response.text
            print('API Error:', response.status_code, response.reason_phrase, error_text)
            return JSONResponse(
                status_code=response.status_code,
                content={
                    "error": "Failed to fetch data from external API",
                    "details": error_text,
                },
            )
        data = response.json()
        return data
    except Exception as error:
        print('Fetch Error:', error)
        return JSONResponse(
            status_code=500,
            content={
                "error": "An internal server error occurred",
                "details": str(error),
            },
        )

@app.get('/networkrail/stations.asmx')
async def network_rail_stations(request: Request):
    API_URL = (
        "https://map-api.production.signalbox.io/api/stations"
    )
    params = dict(request.query_params)
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(API_URL, params=params, timeout=15.0)
        if response.status_code != 200:
            error_text = response.text
            print('API Error:', response.status_code, response.reason_phrase, error_text)
            return JSONResponse(
                status_code=response.status_code,
                content={
                    "error": "Failed to fetch data from external API",
                    "details": error_text,
                },
            )
        data = response.json()
        return data
    except Exception as error:
        print('Fetch Error:', error)
        return JSONResponse(
            status_code=500,
            content={
                "error": "An internal server error occurred",
                "details": str(error),
            },
        )

# Base URLs for the Signalbox API
LOCATIONS_API_URL = "https://map-api.production.signalbox.io/api/locations"
TRAINS_API_URL = "https://map-api.production.signalbox.io/api/trains"


@app.get("/tracking/trains", include_in_schema=False)
async def redir_trains(request: Request):
    trains_url = request.url_for("networkrail_trains")
    return RedirectResponse(url=trains_url, status_code=status.HTTP_303_SEE_OTHER)

@app.get("/networkrail/trains.asmx", name="network_rail_trains")
async def networkrail_tracking(toc: Optional[str] = Query(None, description="Train Operating Company code (optional)"), api_key: str = Depends(get_api_key)):
    """
    Fetches train locations filtered by TOC, or all locations if no TOC is provided,
    including headcode, origin, and destination.
    """
    async with httpx.AsyncClient() as client:
        try:
            # Always fetch all locations
            locations_response = await client.get(LOCATIONS_API_URL)
            locations_response.raise_for_status()
            # *** Added more robust checking and logging for response data ***
            try:
                all_locations_data = locations_response.json()
            except json.JSONDecodeError:
                print(f"Error decoding JSON from {LOCATIONS_API_URL}. Response text: {locations_response.text}")
                raise HTTPException(status_code=500, detail="Error processing locations data from Signalbox API (invalid JSON)")

            all_locations = all_locations_data.get("train_locations", [])
            if not isinstance(all_locations, list):
                 print(f"Warning: 'train_locations' data from {LOCATIONS_API_URL} is not a list, received {type(all_locations)}. Data: {all_locations}")
                 all_locations = []

            all_train_details: List[Dict[str, Any]] = []

            if toc:
                # If TOC is provided, fetch specific train details
                trains_response = await client.get(
                    f"{TRAINS_API_URL}?toc={toc}",
                )
                trains_response.raise_for_status()
                # *** Added more robust checking and logging for response data ***
                try:
                    toc_trains_data = trains_response.json()
                except json.JSONDecodeError:
                     print(f"Error decoding JSON from {TRAINS_API_URL}?toc={toc}. Response text: {trains_response.text}")
                     raise HTTPException(status_code=500, detail=f"Error processing train data for TOC {toc} from Signalbox API (invalid JSON)")

                toc_trains = toc_trains_data.get("trains", [])
                if not isinstance(toc_trains, list):
                     print(f"Warning: 'trains' data from {TRAINS_API_URL}?toc={toc} is not a list, received {type(toc_trains)}. Data: {toc_trains}")
                     toc_trains = []
                all_train_details = toc_trains

            else:
                # If no TOC is provided, fetch train details for ALL TOCs found in locations
                unique_tocs = set(loc.get("toc_code") for loc in all_locations if loc.get("toc_code"))
                print(f"Fetching details for TOCs: {unique_tocs}")

                trains_fetch_tasks = [
                    client.get(f"{TRAINS_API_URL}?toc={t}")
                    for t in unique_tocs
                ]
                trains_responses = await asyncio.gather(*trains_fetch_tasks, return_exceptions=True)

                for i, response in enumerate(trains_responses):
                    current_toc = list(unique_tocs)[i]
                    if isinstance(response, httpx.HTTPStatusError):
                        print(f"HTTP error fetching data for TOC {current_toc}: {response}")
                        continue
                    elif isinstance(response, httpx.RequestError):
                        print(f"Request error fetching data for TOC {current_toc}: {response}")
                        continue
                    elif isinstance(response, Exception):
                        print(f"An unexpected error occurred fetching data for TOC {current_toc}: {response}")
                        continue

                    # *** Added more robust checking and logging for response data ***
                    try:
                        toc_trains_data = response.json()
                    except json.JSONDecodeError:
                        print(f"Error decoding JSON from {TRAINS_API_URL}?toc={current_toc}. Response text: {response.text}")
                        continue # Skip this TOC if JSON decoding fails

                    toc_trains = toc_trains_data.get("trains", [])
                    if not isinstance(toc_trains, list):
                         print(f"Warning: 'trains' data from {TRAINS_API_URL}?toc={current_toc} is not a list, received {type(toc_trains)}. Data: {toc_trains}")
                         continue
                    all_train_details.extend(toc_trains)
            # Create a map of all train details by 'rid' for easy lookup
            all_train_details_map = {
                train.get("rid"): train for train in all_train_details
                if train and isinstance(train, dict) and train.get("rid") and train.get("uid")
            }

            geojson_features: List[Dict[str, Any]] = []

            # Merge locations with train details
            for location_entry in all_locations:
                # *** Added check if location_entry is a dictionary ***
                if not isinstance(location_entry, dict):
                     print(f"Warning: Expected location entry to be a dictionary, received {type(location_entry)}. Entry: {location_entry}")
                     continue # Skip this entry

                linking_rid = location_entry.get("rid")

                if linking_rid and linking_rid in all_train_details_map:
                    train_info = all_train_details_map[linking_rid]

                    location_data = location_entry.get("location")
                    if location_data and isinstance(location_data, dict):
                         latitude = location_data.get("lat")
                         longitude = location_data.get("lon")

                         if latitude is not None and longitude is not None:
                            geojson_features.append({
                                "type": "Feature",
                                "geometry": {
                                    "type": "Point",
                                    "coordinates": [longitude, latitude]
                                },
                                "properties": {
                                    "rid": linking_rid,
                                    "uid": train_info.get("uid"),
                                    "toc": train_info.get("toc_code", location_entry.get("toc_code", "N/A")),
                                    "headcode": train_info.get("headcode", "N/A"),
                                    "delay": train_info.get("delay", location_entry.get("delay", None)),
                                    "destination_name": train_info.get("destination_name", "N/A"),
                                    "origin_name": train_info.get("origin_name", "N/A"),
                                    "origin_departure": train_info.get("origin_departure", "Unknown"),
                                    "ts": location_entry.get("ts"),
                                    "predicted_location": location_entry.get("predicted_location"),
                                    "predicted_ts": location_entry.get("predicted_ts"),
                                     "train_operator": train_info.get("train_operator", "N/A"),
                                }
                            })
                         else:
                            print(f"Warning: Invalid lat/lon data for RID {linking_rid}: {location_data}")
                    else:
                         print(f"Warning: Location object missing 'location' key or is not a dict for RID {linking_rid}: {location_entry}")
        except httpx.HTTPStatusError as e:
             print(f"HTTP error fetching data: {e}")
             error_detail = f"Error fetching data from Signalbox API ({e.request.url}): {e.response.text}"
             raise HTTPException(status_code=e.response.status_code, detail=error_detail)
        except httpx.RequestError as e:
             print(f"Request error fetching data: {e}")
             raise HTTPException(status_code=500, detail=f"Request error fetching data from Signalbox API: {e}")
        except Exception as e:
             print(f"An unexpected error occurred: {e}")
             raise HTTPException(status_code=500, detail=f"An internal server error occurred: {e}")
    return {
        "type": "FeatureCollection",
        "features": geojson_features
    }
