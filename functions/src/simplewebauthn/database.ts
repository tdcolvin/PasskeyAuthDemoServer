import { WebAuthnCredential } from "@simplewebauthn/server";
import * as admin from "firebase-admin";
import { LoggedInUser } from "./example-server";

export async function getUserByUsername(username: string): Promise<LoggedInUser | undefined> {
    const dataSnapshot = await admin.database().ref("users").orderByChild("username").equalTo(username).limitToFirst(1).get();
    if (!dataSnapshot.exists()) {
        return undefined;
    }

    const userAndKey = dataSnapshot.val();
    const keys = Object.keys(userAndKey);
    if (keys.length === 0) {
        return undefined;
    }

    return userAndKey[keys[0]];
}

export async function getUserById(userId: string): Promise<LoggedInUser | undefined> {
    const dataSnapshot = await admin.database().ref("users").child(userId).get();
    return { id: userId, ... dataSnapshot.val() };
}

export async function addUser(userId: string, username: string) {
    await admin.database().ref("users").child(userId).set({ username });
}

export async function addUserCredential(userId: string, credentials: WebAuthnCredential) {
    const user = await getUserById(userId);
    if (!user) {
        throw Error("No such user");
    }

    user.credentials = user.credentials ?? [];
    user.credentials.push(credentials);
    await admin.database().ref("users").child(userId).child("credentials").set(user.credentials);
}

