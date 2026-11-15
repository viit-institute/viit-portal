import { createClient } from "npm:@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function respond(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return respond({ error: "Method not allowed" }, 405);

  try {
    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const anonKey = Deno.env.get("SUPABASE_ANON_KEY");
    const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    if (!supabaseUrl || !anonKey || !serviceKey) {
      return respond({ error: "Server configuration is incomplete" }, 500);
    }

    const body = await req.json();
    const loginId = String(body.login_id || "").trim().toLowerCase();
    const password = String(body.password || "");
    if (!loginId || loginId.length > 100 || !password || password.length > 128) {
      return respond({ error: "Invalid Login ID or password" }, 400);
    }

    const adminClient = createClient(supabaseUrl, serviceKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data: profile, error: profileError } = await adminClient
      .from("profiles")
      .select("id, full_name, login_id, role, phone, program_id")
      .eq("login_id", loginId)
      .maybeSingle();

    if (profileError || !profile) {
      return respond({ error: "Invalid Login ID or password" }, 401);
    }

    const { data: authUser, error: userError } =
      await adminClient.auth.admin.getUserById(profile.id);
    const internalEmail = authUser.user?.email;
    if (userError || !internalEmail) {
      return respond({ error: "Invalid Login ID or password" }, 401);
    }

    const authClient = createClient(supabaseUrl, anonKey, {
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const { data, error } = await authClient.auth.signInWithPassword({
      email: internalEmail,
      password,
    });
    if (error || !data.session || !data.user) {
      return respond({ error: "Invalid Login ID or password" }, 401);
    }

    let programName = null;
    if (profile.program_id) {
      const { data: program } = await adminClient
        .from("programs")
        .select("name")
        .eq("id", profile.program_id)
        .maybeSingle();
      programName = program?.name || null;
    }

    return respond({
      success: true,
      message: "Login successful",
      session: data.session,
      profile: { ...profile, email: internalEmail, program_name: programName },
    });
  } catch (error) {
    console.error("login-with-id error:", error);
    return respond({ error: "Unexpected server error" }, 500);
  }
});