const { supabase } = require('../services/supabase');

// ABAC: permite acceso si el usuario es adoptante (para descuentos)
const requireAdoptant = async (req, res, next) => {
  const { data: profile } = await supabase
    .from('profiles')
    .select('is_adoptant')
    .eq('id', req.user.id)
    .single();

  req.isAdoptant = profile?.is_adoptant || false;
  next(); // no bloquea, solo inyecta el atributo
};

module.exports = { requireAdoptant };