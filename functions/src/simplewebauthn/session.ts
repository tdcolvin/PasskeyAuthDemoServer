import * as admin from "firebase-admin";

export interface SessionInfo {
    expectedChallenge?: string | null;
    requestedUsername?: string | null;
    precreatedUserId?: string | null;
    signInUsername?: string | null;
}

function verifySafeSessionId(sessionId: string) {
    if(!sessionId.match("^[0-9a-zA-Z_-]+$")) {
        throw Error("Bad session ID");
    }
}

export async function updateSession(sessionId: string, sessionInfo: SessionInfo) {
    verifySafeSessionId(sessionId);
    await admin.database().ref("sessions").child(sessionId).update(sessionInfo);
}

export async function getSession(sessionId: string): Promise<SessionInfo> {
    verifySafeSessionId(sessionId);
    const dataSnapshot = await admin.database().ref("sessions").child(sessionId).get();
    return dataSnapshot.val() as SessionInfo;
}