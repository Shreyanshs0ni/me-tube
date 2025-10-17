import { headers } from "next/headers";
import { Webhook } from "svix";
import { WebhookEvent } from "@clerk/nextjs/server";
import { db } from "@/db";
import { users } from "@/db/schema";
import { eq } from "drizzle-orm";

/**
 * Clerk sends signed webhooks using Svix.
 * You must verify the signature using your CLERK_WEBHOOK_SECRET.
 */
export async function POST(req: Request) {
  // Clerk Webhook Secret from environment variables
  const SIGNING_SECRET = process.env.CLERK_SIGNING_SECRET;

  if (!SIGNING_SECRET) {
    throw new Error(
      "Error: Please add SIGNING_SECRET from Clerk Dashboard to .env or .env.local"
    );
  }
  //Create new svix instance with secret
  const wh = new Webhook(SIGNING_SECRET);
  // Get headers for signature verification
  const headerPayload = await headers();
  const svix_id = headerPayload.get("svix-id");
  const svix_timestamp = headerPayload.get("svix-timestamp");
  const svix_signature = headerPayload.get("svix-signature");

  if (!svix_id || !svix_timestamp || !svix_signature) {
    return new Response("Missing Svix headers", { status: 400 });
  }

  // Get the raw body of the webhook request
  const payload = await req.json();
  const body = JSON.stringify(payload);

  let evt: WebhookEvent;

  try {
    // Verify the webhook payload and signature
    evt = wh.verify(body, {
      "svix-id": svix_id,
      "svix-timestamp": svix_timestamp,
      "svix-signature": svix_signature,
    }) as WebhookEvent;
  } catch (err) {
    console.error("❌ Error verifying webhook:", err);
    return new Response("Invalid signature", { status: 400 });
  }

  // Do something with the payload
  // For this guide, log payload to console
  const eventType = evt.type;

  // Handle specific event types
  if (eventType === "user.created") {
    const { data } = evt;
    await db.insert(users).values({
      clerkId: data.id,
      name: `${data.first_name} ${data.last_name}`,
      imageUrl: data.image_url,
    });
  }
  if (eventType === "user.deleted") {
    const { data } = evt;
    if (!data.id) {
      return new Response("Missing User Id", { status: 400 });
    }
    await db.delete(users).where(eq(users.clerkId, data.id));
  }

  if (eventType === "user.updated") {
    const { data } = evt;
    await db
      .update(users)
      .set({
        name: `${data.first_name} ${data.last_name}`,
        imageUrl: data.image_url,
      })
      .where(eq(users.clerkId, data.id));
  }

  // Always respond 200 to acknowledge receipt
  return new Response("Webhook received", { status: 200 });
}
