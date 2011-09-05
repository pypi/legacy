CREATE TABLE openid_whitelist
(
  "name" text NOT NULL,
  trust_root text NOT null,
  created timestamp without time zone,
  CONSTRAINT openid_whitelist__pkey PRIMARY KEY (name, trust_root)
);
