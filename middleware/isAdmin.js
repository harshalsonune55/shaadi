export function isAdmin(req, res, next) {
    if (!req.isAuthenticated() || !req.user?.isAdmin) {
      return res.status(403).send("Access Denied");
    }
    next();
  }
  