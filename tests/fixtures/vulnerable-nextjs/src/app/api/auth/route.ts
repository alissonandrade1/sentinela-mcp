// ❌ VULNERÁVEL — API route com múltiplos problemas

import { NextResponse } from "next/server";

export async function POST(req: Request) {
  try {
    const body = await req.json();

    // 🔴 SENT-LOG: logando req.body inteiro (pode conter senha)
    console.log("Login attempt:", req.body);

    // 🔴 SENT-DES: eval com dados do usuário
    const config = eval(body.configString);

    // Simular login...
    const user = await authenticateUser(body.email, body.password);

    if (!user) {
      return NextResponse.json({ error: "Invalid credentials" });
    }

    // 🔴 SENT-LOG: logando token
    console.log("User token:", user.token);

    return NextResponse.json({ user });
  } catch (error: any) {
    // 🔴 SENT-ERR: erro raw enviado ao cliente
    return NextResponse.json({ error: error.message, stack: error.stack });
  }
}

async function authenticateUser(email: string, password: string) {
  // placeholder
  return null;
}
