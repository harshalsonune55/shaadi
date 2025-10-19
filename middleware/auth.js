// middleware/auth.js

export function isLoggedIn(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    // You can store the URL they were trying to access and redirect them after login
    req.session.returnTo = req.originalUrl;
    res.redirect("/login");
}