const { supabase } = require('../services/supabase');

exports.getAll = async (req, res) => {
  const { data } = await supabase.from('products').select('*');
  res.json(data);
};

exports.getWithDiscount = async (req, res) => {
  // Usa la vista que aplica ABAC (descuento adoptantes)
  const { data } = await supabase.from('products_with_discount').select('*');
  res.json(data);
};

exports.create = async (req, res) => {
  const { name, description, price, discounted_price, stock, category } = req.body;
  const { data, error } = await supabase
    .from('products').insert({ name, description, price, discounted_price, stock, category }).select();
  if (error) return res.status(400).json({ error: error.message });
  res.json(data[0]);
};