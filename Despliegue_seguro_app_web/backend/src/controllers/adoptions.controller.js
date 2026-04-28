const { supabase } = require('../services/supabase');

exports.getPets = async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('pets')
      .select('*')
      .eq('status', 'disponible');
    if (error) return res.status(500).json({ error: error.message });
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
};

exports.getAll = async (req, res) => {
  const { data } = await supabase.from('adoptions').select('*, pets(*)');
  res.json(data);
};

exports.adopt = async (req, res) => {
  const { pet_id } = req.body;
  const user_id = req.user.id;

  await supabase.from('pets').update({ status: 'adoptado' }).eq('id', pet_id);

  const { data } = await supabase.from('adoptions').insert({ pet_id, user_id }).select();

  await supabase.from('profiles').update({ is_adoptant: true }).eq('id', user_id);

  res.json({ message: '¡Adopción completada! Ya tienes acceso a descuentos exclusivos.', adoption: data[0] });
};

exports.createPet = async (req, res) => {
  try {
    const { name, species, age, description } = req.body;

    const { data, error } = await supabase
      .from('pets')
      .insert([{ name, species, age, description, status: 'disponible' }])
      .select();

    if (error) return res.status(500).json({ error: error.message });
    res.status(201).json(data[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
};