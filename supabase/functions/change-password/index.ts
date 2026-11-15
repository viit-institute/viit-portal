import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const json = (body: Record<string, unknown>, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ success: false, message: "Method not allowed." }, 405);

  try {
    const authHeader = req.headers.get("Authorization");
    if (!authHeader?.startsWith("Bearer ")) {
      return json({ success: false, message: "Please log in first." }, 401);
    }

    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
    const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!supabaseUrl || !anonKey || !serviceKey) {
      return json({ success: false, message: "Server configuration is incomplete." }, 500);
    }

    const accessToken = authHeader.slice(7);
    const callerClient = createClient(supabaseUrl, anonKey, {
      global: { headers: { Authorization: `Bearer ${accessToken}` } },
      auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
    });
    const { data: callerData, error: callerError } = await callerClient.auth.getUser(accessToken);
    const user = callerData.user;
    if (callerError || !user?.email) {
      return json({ success: false, message: "Your session is invalid. Please log in again." }, 401);
    }

    const body = await req.json();
    const currentPassword = body.current_password;
    const newPassword = body.new_password;
    const confirmPassword = body.confirm_password;

    if (typeof currentPassword !== "string" || typeof newPassword !== "string" ||
        typeof confirmPassword !== "string" || !currentPassword || !newPassword || !confirmPassword) {
      return json({ success: false, message: "Please fill in all password fields." }, 400);
    }
    if (newPassword.length < 8 || newPassword.length > 128) {
      return json({ success: false, message: "New password must be between 8 and 128 characters." }, 400);
    }
    if (newPassword !== confirmPassword) {
      return json({ success: false, message: "New passwords do not match." }, 400);
    }
    if (currentPassword === newPassword) {
      return json({ success: false, message: "New password must be different from the current password." }, 400);
    }

    const verifyClient = createClient(supabaseUrl, anonKey, {
      auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
    });
    const { error: verifyError } = await verifyClient.auth.signInWithPassword({
      email: user.email,
      password: currentPassword,
    });
    if (verifyError) {
      return json({ success: false, message: "Current password is incorrect." }, 400);
    }

    const adminClient = createClient(supabaseUrl, serviceKey, {
      auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
    });
    const { error: updateError } = await adminClient.auth.admin.updateUserById(user.id, {
      password: newPassword,
    });
    if (updateError) {
      console.error("Password update error:", updateError);
      return json({ success: false, message: "Password could not be updated. Please try again." }, 400);
    }

    return json({ success: true, message: "Password changed successfully." });
  } catch (error) {
    console.error("Change password error:", error);
    return json({ success: false, message: "Unable to change password. Please try again." }, 500);
  }
});
