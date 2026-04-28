const { supabase } = require('../services/supabase');

exports.getAll = async (req, res) => {
  const { data: profile } = await supabase
    .from('profiles')
    .select('role')
    .eq('id', req.user.id)
    .single();

  let query = supabase.from('appointments').select('*').order('date', { ascending: true });

  // ABAC: cliente solo ve sus propias citas
  if (profile?.role === 'cliente') {
    query = query.eq('user_id', req.user.id);
  }

  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
};

exports.create = async (req, res) => {
  const { pet_name, date, notes, vet_id } = req.body;
  const { data, error } = await supabase
    .from('appointments')
    .insert({ user_id: req.user.id, pet_name, date, notes, vet_id })
    .select();
  if (error) return res.status(400).json({ error: error.message });
  res.json(data[0]);
};

exports.updateStatus = async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  const { data, error } = await supabase
    .from('appointments')
    .update({ status })
    .eq('id', id)
    .select();
  if (error) return res.status(400).json({ error: error.message });
  res.json(data[0]);
};