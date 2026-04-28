const { supabase } = require('../services/supabase');

const rbac = (...allowedRoles) => async (req, res, next) => {
  const { data: profile } = await supabase
    .from('profiles')
    .select('role')
    .eq('id', req.user.id)
    .single();

  if (!profile || !allowedRoles.includes(profile.role))
    return res.status(403).json({ error: 'Forbidden: insufficient role' });

  req.userRole = profile.role;
  next();
};

module.exports = rbac;