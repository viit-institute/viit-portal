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

  let createdUserId: string | null = null;
  try {
    const authHeader = req.headers.get("Authorization");
    if (!authHeader?.startsWith("Bearer ")) {
      return json({ success: false, message: "Admin login required." }, 401);
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
    if (callerError || !callerData.user) {
      return json({ success: false, message: "Your session is invalid. Please log in again." }, 401);
    }

    const adminClient = createClient(supabaseUrl, serviceKey, {
      auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
    });
    const { data: callerProfile, error: profileError } = await adminClient
      .from("profiles")
      .select("id, role")
      .eq("id", callerData.user.id)
      .maybeSingle();

    if (profileError || callerProfile?.role !== "admin") {
      return json({ success: false, message: "Only a VIIT Admin can create accounts." }, 403);
    }

    const body = await req.json();
    const fullName = String(body.full_name || "").trim();
    const email = String(body.email || "").trim().toLowerCase();
    const loginId = String(body.login_id || "").trim().toLowerCase();
    const password = String(body.password || "");
    const role = String(body.role || "");
    const course = body.course == null ? null : String(body.course).trim();

    if (!fullName || fullName.length > 120 ||
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254 ||
        !/^[a-z0-9._-]{3,50}$/.test(loginId) ||
        password.length < 8 || password.length > 128 ||
        !["student", "staff"].includes(role)) {
      return json({ success: false, message: "Please check the account details. Login ID must be 3-50 valid characters and password at least 8 characters." }, 400);
    }

    const { data: existing, error: existingError } = await adminClient
      .from("profiles")
      .select("id")
      .eq("login_id", loginId)
      .maybeSingle();
    if (existingError) return json({ success: false, message: "Could not validate the Login ID." }, 500);
    if (existing) return json({ success: false, message: "This Login ID is already in use." }, 409);

    let programId: string | null = null;
    if (role === "student") {
      if (!course) return json({ success: false, message: "Please select a course for the student." }, 400);
      const { data: program, error: programError } = await adminClient
        .from("programs")
        .select("id")
        .eq("name", course)
        .eq("is_active", true)
        .maybeSingle();
      if (programError || !program) {
        return json({ success: false, message: "Selected course was not found in the VIIT programs list." }, 400);
      }
      programId = program.id;
    }

    const { data: created, error: createError } = await adminClient.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: { full_name: fullName, login_id: loginId, role, course },
    });
    if (createError || !created.user) {
      return json({ success: false, message: createError?.message || "Could not create the authentication account." }, 400);
    }
    createdUserId = created.user.id;

    const { data: profile, error: insertError } = await adminClient
      .from("profiles")
      .insert({
        id: createdUserId,
        full_name: fullName,
        login_id: loginId,
        role,
        phone: null,
        program_id: programId,
      })
      .select("id, full_name, login_id, role, phone, program_id")
      .single();

    if (insertError || !profile) {
      await adminClient.auth.admin.deleteUser(createdUserId);
      createdUserId = null;
      if (insertError?.code === "23505") {
        return json({ success: false, message: "This Login ID or profile already exists." }, 409);
      }
      console.error("Profile insert error:", insertError);
      return json({ success: false, message: "Authentication user was rolled back because the VIIT profile could not be created." }, 500);
    }

    if (role === "student" && programId) {
      const { error: enrollmentError } = await adminClient
        .from("enrollments")
        .insert({ student_id: createdUserId, program_id: programId, status: "active" });
      if (enrollmentError) {
        await adminClient.from("profiles").delete().eq("id", createdUserId);
        await adminClient.auth.admin.deleteUser(createdUserId);
        createdUserId = null;
        console.error("Enrollment insert error:", enrollmentError);
        return json({ success: false, message: "Account was rolled back because student enrollment could not be saved." }, 500);
      }
    }

    return json({ success: true, message: "Account created.", profile }, 201);
  } catch (error) {
    console.error("Admin create user error:", error);
    return json({ success: false, message: "Unexpected server error." }, 500);
  }
});
