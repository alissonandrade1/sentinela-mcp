// ❌ VULNERÁVEL — Arquivo com problemas propositais para testar o Sentinela

import { createClient } from "@supabase/supabase-js";

// 🔴 SENT-SEC: API key hardcoded
const supabase = createClient(
  "https://abc123.supabase.co",
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSJ9.hardcoded_secret_key_here"
);

// 🔴 SENT-SEC: Stripe key hardcoded
const stripe_key = "sk_live_51abc123def456ghi789jklmnopqrst";

// 🔴 SENT-SEC: Connection string com senha
const db_url = "postgres://admin:supersecretpassword123@db.example.com:5432/mydb";

export async function getUsers() {
  const { data } = await supabase.from("users").select("*");
  return data;
}
