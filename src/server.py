import os
import json
import secrets
from typing import Optional

try:
    from fastapi import FastAPI, Request, Form, Response, Cookie, Depends, HTTPException, status
    from fastapi.security import HTTPBasic, HTTPBasicCredentials
    from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
    from fastapi.staticfiles import StaticFiles
    from fastapi.templating import Jinja2Templates
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")

if FASTAPI_AVAILABLE:
    app = FastAPI(title="IdentityNet Gateway Server", version="2.0.0")
    admin_basic = HTTPBasic(auto_error=False)

    if os.path.exists(STATIC_DIR):
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    templates = Jinja2Templates(directory=TEMPLATES_DIR)
else:
    app = None
    templates = None
    admin_basic = None
    Depends = lambda dependency: None

# Global Manager References (Set by main.py during startup)
db_manager = None
policy_engine = None
firewall_manager = None
router_manager = None
gateway_ip = "127.0.0.1"
lan_subnet = "192.168.137.0/24"

def require_admin(credentials: "HTTPBasicCredentials" = Depends(admin_basic)):
    """Require the administrator password configured in IDENTITYNET_ADMIN_PASSWORD."""
    expected_password = os.environ.get("IDENTITYNET_ADMIN_PASSWORD")
    if not expected_password:
        raise HTTPException(status_code=503, detail="Set IDENTITYNET_ADMIN_PASSWORD before using the admin interface")
    if not credentials or not secrets.compare_digest(credentials.username, "admin") or not secrets.compare_digest(credentials.password, expected_password):
        raise HTTPException(status_code=401, detail="Administrator authentication required", headers={"WWW-Authenticate": "Basic"})
    return credentials.username

def get_client_ip(request) -> str:
    """Extract client IPv4 address from request."""
    if hasattr(request, "client") and request.client:
        return request.client.host
    return "127.0.0.1"

def render_template(request: Request, template_name: str, context: dict, status_code: int = 200):
    """Helper for starlette/fastapi version-compatible template response."""
    context["request"] = request
    try:
        return templates.TemplateResponse(name=template_name, context=context, status_code=status_code)
    except Exception:
        return templates.TemplateResponse(request, template_name, context, status_code=status_code)

if FASTAPI_AVAILABLE:
    # =============================================================================
    # Participant Authentication & Contest Routes
    # =============================================================================

    @app.get("/", response_class=HTMLResponse)
    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request, identitynet_session: Optional[str] = Cookie(None)):
        """Render Participant Login Page."""
        if identitynet_session and db_manager:
            session = db_manager.get_session_by_id(identitynet_session)
            if session:
                return RedirectResponse(url="/contest", status_code=status.HTTP_303_SEE_OTHER)
        return render_template(request, "login.html", {"error": None})

    @app.post("/login")
    async def login_submit(
        request: Request,
        participant_id: str = Form(...),
        password: str = Form(...)
    ):
        """Authenticate Participant and create active session."""
        client_ip = get_client_ip(request)
        auth_user = db_manager.authenticate_participant(participant_id.strip(), password.strip()) if db_manager else None
        
        if not auth_user:
            return render_template(
                request,
                "login.html",
                {"error": "Invalid Participant ID or Password. Please try again."},
                status_code=status.HTTP_401_UNAUTHORIZED
            )

        # Create active session in SQLite DB
        session_id = db_manager.create_session(participant_id.strip(), client_ip)
        
        response = RedirectResponse(url="/contest", status_code=status.HTTP_303_SEE_OTHER)
        response.set_cookie(key="identitynet_session", value=session_id, httponly=True, max_age=86400)
        return response

    @app.get("/contest", response_class=HTMLResponse)
    async def contest_page(request: Request, identitynet_session: Optional[str] = Cookie(None)):
        """Render Contest Workspace Page for authenticated participant."""
        if not identitynet_session or not db_manager:
            return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

        session = db_manager.get_session_by_id(identitynet_session)
        if not session:
            return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

        questions = db_manager.get_questions()
        active_profile = policy_engine.active_profile_name if policy_engine else "contest-2026"
        
        return render_template(
            request,
            "contest.html",
            {
                "participant": session,
                "questions": questions,
                "profile": active_profile
            }
        )

    @app.get("/questions")
    async def get_questions_api():
        """Return JSON list of contest questions."""
        if not db_manager:
            return JSONResponse([])
        return JSONResponse(db_manager.get_questions())

    @app.post("/submit")
    async def submit_code(
        request: Request,
        question_id: int = Form(...),
        code: str = Form(...),
        identitynet_session: Optional[str] = Cookie(None)
    ):
        """Handle problem submission."""
        if not identitynet_session or not db_manager:
            raise HTTPException(status_code=401, detail="Unauthorized")
        
        session = db_manager.get_session_by_id(identitynet_session)
        if not session:
            raise HTTPException(status_code=401, detail="Session expired")

        result = db_manager.record_submission(session["participant_id"], question_id, code)
        return JSONResponse({"status": "SUCCESS", "message": "Solution submitted and accepted!", "submission": result})

    @app.get("/logout")
    async def logout(response: Response):
        """Logout participant."""
        res = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
        res.delete_cookie("identitynet_session")
        return res

    # =============================================================================
    # Admin Control Dashboard & Network API Routes
    # =============================================================================

    @app.get("/admin", response_class=HTMLResponse)
    async def admin_dashboard(request: Request, _: str = Depends(require_admin)):
        """Render Admin Monitoring Dashboard UI."""
        return render_template(request, "admin.html", {})

    @app.get("/api/admin/status")
    async def admin_status_api(_: str = Depends(require_admin)):
        """Return Gateway system network status."""
        participants = db_manager.get_active_sessions() if db_manager else []
        return JSONResponse({
            "gateway": "ONLINE",
            "network": "IdentityNet-Hotspot",
            "subnet": lan_subnet,
            "gateway_ip": gateway_ip,
            "dns": "IdentityNet Policy Resolver (Port 53)",
            "nat": "ACTIVE",
            "firewall": "ACTIVE (Default-Deny)",
            "policy_profile": policy_engine.active_profile_name if policy_engine else "contest-2026",
            "active_participants_count": len(participants)
        })

    @app.get("/api/admin/participants")
    async def admin_participants_api(_: str = Depends(require_admin)):
        """Return all participant accounts with status and access statistics."""
        if not db_manager:
            return JSONResponse([])
        return JSONResponse(db_manager.get_participants_with_access_stats())

    @app.post("/api/admin/participants")
    async def admin_create_participant_api(request: Request, _: str = Depends(require_admin)):
        """Create a participant account from the admin dashboard."""
        if not db_manager:
            raise HTTPException(status_code=503, detail="Database is not available")
        body = await request.json()
        if not isinstance(body, dict):
            raise HTTPException(status_code=400, detail="Request body must be a JSON object")
        try:
            participant = db_manager.create_participant(
                body.get("participant_id", ""),
                body.get("name", ""),
                body.get("password", ""),
            )
        except (AttributeError, TypeError, ValueError) as error:
            raise HTTPException(status_code=400, detail=str(error)) from error
        return JSONResponse(participant, status_code=201)

    @app.get("/api/admin/events")
    @app.get("/api/admin/application-access")
    async def admin_events_api(limit: int = 50, _: str = Depends(require_admin)):
        """Return recent application access attempts (User Name and Application alone)."""
        if not db_manager:
            return JSONResponse([])
        return JSONResponse(db_manager.get_recent_application_access(limit=limit))

    @app.get("/api/admin/application-events")
    async def admin_application_events_api(limit: int = 50, _: str = Depends(require_admin)):
        """Return recent V2 application detections and enforcement decisions."""
        if not db_manager:
            return JSONResponse([])
        return JSONResponse(db_manager.get_recent_application_events(limit=limit))

    @app.get("/api/admin/policy")
    async def admin_get_policy_api(_: str = Depends(require_admin)):
        """Return current policy allowlist."""
        if not policy_engine:
            return JSONResponse({})
        return JSONResponse({
            "active_profile": policy_engine.active_profile_name,
            "mode": policy_engine.mode,
            "allowed": policy_engine.allowed_domains,
            "user_policies": policy_engine.get_user_allowed_domains(),
            "blocked_explicit": policy_engine.blocked_explicit,
            "blocked_categories": policy_engine.blocked_categories,
            "blocked_apps": policy_engine.blocked_apps
        })

    @app.post("/api/admin/policy/add")
    async def admin_add_policy_domain(request: Request, _: str = Depends(require_admin)):
        """Dynamically add domain to policy allowlist."""
        body = await request.json()
        domain = body.get("domain", "").strip()
        if not domain or not policy_engine:
            raise HTTPException(status_code=400, detail="Invalid domain")
        
        success = policy_engine.add_allowed_domain(domain)
        return JSONResponse({"status": "SUCCESS" if success else "EXISTS", "domain": domain, "allowed": policy_engine.allowed_domains})

    @app.post("/api/admin/policy/remove")
    async def admin_remove_policy_domain(request: Request, _: str = Depends(require_admin)):
        """Dynamically remove domain from policy allowlist."""
        body = await request.json()
        domain = body.get("domain", "").strip()
        if not domain or not policy_engine:
            raise HTTPException(status_code=400, detail="Invalid domain")
        
        success = policy_engine.remove_allowed_domain(domain)
        return JSONResponse({"status": "SUCCESS" if success else "NOT_FOUND", "domain": domain, "allowed": policy_engine.allowed_domains})

    @app.post("/api/admin/policy/user/add")
    async def admin_add_user_policy_domain(request: Request, _: str = Depends(require_admin)):
        """Add a site to one participant's local allowlist."""
        body = await request.json()
        user = body.get("user", "").strip()
        domain = body.get("domain", "").strip()
        if not user or not domain or not policy_engine:
            raise HTTPException(status_code=400, detail="User and domain are required")
        success = policy_engine.add_user_allowed_domain(user, domain)
        return JSONResponse({"status": "SUCCESS" if success else "EXISTS"})

    @app.post("/api/admin/policy/user/remove")
    async def admin_remove_user_policy_domain(request: Request, _: str = Depends(require_admin)):
        """Remove a site from one participant's local allowlist."""
        body = await request.json()
        user = body.get("user", "").strip()
        domain = body.get("domain", "").strip()
        if not user or not domain or not policy_engine:
            raise HTTPException(status_code=400, detail="User and domain are required")
        success = policy_engine.remove_user_allowed_domain(user, domain)
        return JSONResponse({"status": "SUCCESS" if success else "NOT_FOUND"})

    @app.post("/api/admin/policy/profile")
    async def admin_switch_profile(request: Request, _: str = Depends(require_admin)):
        """Switch active profile (e.g. 'contest-2026' vs 'exam-2026')."""
        body = await request.json()
        profile_name = body.get("profile", "").strip()
        if not profile_name or not policy_engine:
            raise HTTPException(status_code=400, detail="Invalid profile")
        
        success = policy_engine.set_active_profile(profile_name)
        return JSONResponse({"status": "SUCCESS" if success else "FAILED", "active_profile": policy_engine.active_profile_name})
