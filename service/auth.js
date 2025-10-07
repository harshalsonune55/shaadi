
const sessionIdToUserIdMap = new Map();

export function setUser(id, user) {
    return sessionIdToUserIdMap.set(id, user);
}

export function getUser(id) {
    return sessionIdToUserIdMap.get(id);
}

