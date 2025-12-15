// middleware/auth.js

export function isLoggedIn(req, res, next) {
    if (req.isAuthenticated && req.isAuthenticated()) {
        return next();
    }

    // If request expects JSON (OTP / API / fetch)
    if (req.headers.accept?.includes("application/json")) {
        return res.status(401).json({
            success: false,
            error: "Authentication required"
        });
    }

    // For normal browser navigation
    req.session.returnTo = req.originalUrl;
    return res.redirect("/login");
}
