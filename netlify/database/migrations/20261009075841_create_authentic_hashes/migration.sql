CREATE TABLE "authentic_hashes" (
	"id" serial PRIMARY KEY,
	"file_name" text NOT NULL,
	"hash_value" text NOT NULL UNIQUE,
	"created_at" timestamp DEFAULT now()
);
