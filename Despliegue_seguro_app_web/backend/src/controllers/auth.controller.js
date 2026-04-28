const { supabase, supabaseAdmin } = require('../services/supabase');

// Registrar usuario
exports.register = async (req, res) => {
  const { email, password, full_name } = req.body;
  const { data, error } = await supabase.auth.admin.createUser({
    email, password,
    user_metadata: { full_name }
  });
  if (error) return res.status(400).json({ error: error.message });

  await supabase.from('profiles').insert({
    id: data.user.id, email, full_name, role: 'cliente'
  });

  res.json({ message: 'Usuario creado', user: data.user });
};

// Login
exports.login = async (req, res) => {
  const { email, password } = req.body;
  const { data, error } = await supabase.auth.signInWithPassword({ email, password });
  if (error) return res.status(401).json({ error: error.message });

  const { data: profile } = await supabase
    .from('profiles')
    .select('role')
    .eq('id', data.user.id)
    .single();

  res.json({
    token: data.session.access_token,
    user: data.user,
    role: profile?.role || 'cliente'
  });
};

// Obtener perfil propio
exports.getProfile = async (req, res) => {
  const { data } = await supabase
    .from('profiles').select('*').eq('id', req.user.id).single();
  res.json(data);
};

// Iniciar OAuth con GitHub
exports.githubLogin = async (req, res) => {
  const { data, error } = await supabase.auth.signInWithOAuth({
    provider: 'github',
    options: {
      redirectTo: 'http://localhost:3000/api/auth/github/callback'
    }
  });
  if (error) return res.status(500).json({ error: error.message });
  res.redirect(data.url);
};

// Callback de GitHub
exports.githubCallback = async (req, res) => {
  const { code } = req.query;

  const { data, error } = await supabase.auth.exchangeCodeForSession(code);
  if (error) return res.redirect('http://localhost:5173/login?error=oauth_failed');

  const user = data.user;
  const token = data.session.access_token;

  const { data: existing } = await supabase
    .from('profiles')
    .select('id, role')
    .eq('id', user.id)
    .single();

  if (!existing) {
    await supabase.from('profiles').insert({
      id: user.id,
      email: user.email,
      full_name: user.user_metadata?.full_name || user.user_metadata?.user_name || '',
      role: 'cliente'
    });
  }

  const role = existing?.role || 'cliente';

  res.redirect(`http://localhost:5173/oauth-callback?token=${token}&role=${role}&user=${encodeURIComponent(JSON.stringify({ id: user.id, email: user.email }))}`);
};