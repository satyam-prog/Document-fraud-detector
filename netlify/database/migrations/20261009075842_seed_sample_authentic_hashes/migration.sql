INSERT INTO "authentic_hashes" ("file_name", "hash_value") VALUES
  ('sample_doc_001.pdf', '3d7e8f3b6b40d26a0db1d0b1176900d0100c166d61247d2e1d3d17d7b1d7f9d1'),
  ('sample_id_card.jpg', '9c7af7e6ea1601955c5b2ad5d9d182856455271ec7f9b9d30e56dcf6f0443d12'),
  ('sample_certificate.png', 'b1d9a2ce48d4204b8a2e7ff7df2d917a8d028b25d3f516eb3a9b204f420b4d5f')
ON CONFLICT ("hash_value") DO NOTHING;
