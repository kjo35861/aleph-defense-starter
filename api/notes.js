// Step 2: server-only Supabase access. Do not expose environment values.
import { createClient } from '@supabase/supabase-js';

export default async function handler(_request, response) {
  response.setHeader('Cache-Control', 'no-store');

  const url = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!url || !secretKey) {
    response.status(500).json({ error: 'SERVER_NOT_CONFIGURED' });
    return;
  }

  const supabase = createClient(url, secretKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  });

  const { data, error } = await supabase
    .from('learning_notes')
    .select('title, content')
    .order('id', { ascending: true });

  if (error) {
    response.status(500).json({ error: 'NOTES_UNAVAILABLE' });
    return;
  }

  response.status(200).json({ notes: data ?? [] });
}
