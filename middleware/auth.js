import { getuser } from "../service/auth";
async function restricttologinuser(req, res, next) {
    const sessionId = req.cookies?.sessionId;
    if (!sessionId) {
        return res.redirect("/login");
    }
    const user=getuser(sessionId);
    if (!user) {
        return res.redirect("/login");
    }
    req.user=user;
    next();
}

module.exports = { restricttologinuser };