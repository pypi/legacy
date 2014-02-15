-- THIS FILE IS OUT OF DATE

-- Database creation is now under the control of the Warehouse project. This
-- file does not reflect the current schema of the PyPI service.

-- NOTE: PyPI requires the citext extension

SET statement_timeout = 0;
SET lock_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET check_function_bodies = false;
SET client_min_messages = warning;

SET search_path = public, pg_catalog;

SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: accounts_email; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE accounts_email (
    id integer NOT NULL,
    user_id integer NOT NULL,
    email character varying(254) NOT NULL,
    "primary" boolean NOT NULL,
    verified boolean NOT NULL
);


--
-- Name: accounts_email_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE accounts_email_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: accounts_email_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE accounts_email_id_seq OWNED BY accounts_email.id;


--
-- Name: accounts_gpgkey; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE accounts_gpgkey (
    id integer NOT NULL,
    user_id integer NOT NULL,
    key_id citext NOT NULL,
    verified boolean NOT NULL,
    CONSTRAINT accounts_gpgkey_valid_key_id CHECK ((key_id ~* '^[A-F0-9]{8}$'::citext))
);


--
-- Name: accounts_gpgkey_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE accounts_gpgkey_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: accounts_gpgkey_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE accounts_gpgkey_id_seq OWNED BY accounts_gpgkey.id;


--
-- Name: accounts_user; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE accounts_user (
    id integer NOT NULL,
    password character varying(128) NOT NULL,
    last_login timestamp with time zone NOT NULL,
    is_superuser boolean NOT NULL,
    username citext NOT NULL,
    name character varying(100) NOT NULL,
    is_staff boolean NOT NULL,
    is_active boolean NOT NULL,
    date_joined timestamp with time zone DEFAULT now(),
    CONSTRAINT accounts_user_username_length CHECK ((length((username)::text) <= 50)),
    CONSTRAINT accounts_user_valid_username CHECK ((username ~* '^([A-Z0-9]|[A-Z0-9][A-Z0-9._-]*[A-Z0-9])$'::citext))
);


--
-- Name: accounts_user_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE accounts_user_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: accounts_user_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE accounts_user_id_seq OWNED BY accounts_user.id;


--
-- Name: alembic_version; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE alembic_version (
    version_num character varying(32) NOT NULL
);


SET default_with_oids = true;

--
-- Name: browse_tally; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE browse_tally (
    trove_id integer NOT NULL,
    tally integer
);


--
-- Name: cheesecake_main_indices; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE cheesecake_main_indices (
    id integer NOT NULL,
    absolute integer NOT NULL,
    relative integer NOT NULL
);


--
-- Name: cheesecake_main_indices_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE cheesecake_main_indices_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: cheesecake_main_indices_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE cheesecake_main_indices_id_seq OWNED BY cheesecake_main_indices.id;


--
-- Name: cheesecake_subindices; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE cheesecake_subindices (
    main_index_id integer NOT NULL,
    name text NOT NULL,
    value integer NOT NULL,
    details text NOT NULL
);


SET default_with_oids = false;

--
-- Name: comments; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE comments (
    id integer NOT NULL,
    rating integer,
    user_name citext,
    date timestamp without time zone,
    message text,
    in_reply_to integer
);


--
-- Name: comments_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE comments_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: comments_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE comments_id_seq OWNED BY comments.id;


--
-- Name: comments_journal; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE comments_journal (
    name text,
    version text,
    id integer,
    submitted_by citext,
    date timestamp without time zone,
    action text
);


--
-- Name: cookies; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE cookies (
    cookie text NOT NULL,
    name citext,
    last_seen timestamp without time zone
);


--
-- Name: csrf_tokens; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE csrf_tokens (
    name citext NOT NULL,
    token text,
    end_date timestamp without time zone
);


SET default_with_oids = true;

--
-- Name: description_urls; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE description_urls (
    name text,
    version text,
    url text,
    id integer NOT NULL
);


--
-- Name: description_urls_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE description_urls_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: description_urls_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE description_urls_id_seq OWNED BY description_urls.id;


--
-- Name: dual; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE dual (
    dummy integer
);


--
-- Name: journals; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE journals (
    name text,
    version text,
    action text,
    submitted_date timestamp without time zone,
    submitted_by citext,
    submitted_from text,
    id integer NOT NULL
);


--
-- Name: journals_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE journals_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: journals_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE journals_id_seq OWNED BY journals.id;


SET default_with_oids = false;

--
-- Name: mirrors; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE mirrors (
    ip text NOT NULL,
    user_name citext,
    index_url text,
    last_modified_url text,
    local_stats_url text,
    stats_url text,
    mirrors_url text
);


--
-- Name: oauth_access_tokens; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE oauth_access_tokens (
    token character varying(32) NOT NULL,
    secret character varying(64) NOT NULL,
    consumer character varying(32) NOT NULL,
    date_created date NOT NULL,
    last_modified date NOT NULL,
    user_name citext
);


--
-- Name: oauth_consumers; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE oauth_consumers (
    consumer character varying(32) NOT NULL,
    secret character varying(64) NOT NULL,
    date_created date NOT NULL,
    created_by citext,
    last_modified date NOT NULL,
    description character varying(255) NOT NULL
);


--
-- Name: oauth_nonce; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE oauth_nonce (
    "timestamp" integer NOT NULL,
    consumer character varying(32) NOT NULL,
    nonce character varying(32) NOT NULL,
    token character varying(32)
);


--
-- Name: oauth_request_tokens; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE oauth_request_tokens (
    token character varying(32) NOT NULL,
    secret character varying(64) NOT NULL,
    consumer character varying(32) NOT NULL,
    callback text,
    date_created date NOT NULL,
    user_name citext
);


--
-- Name: oid_associations; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE oid_associations (
    server_url character varying(2047) NOT NULL,
    handle character varying(255) NOT NULL,
    secret bytea NOT NULL,
    issued integer NOT NULL,
    lifetime integer NOT NULL,
    assoc_type character varying(64) NOT NULL,
    CONSTRAINT secret_length_constraint CHECK ((length(secret) <= 128))
);


--
-- Name: oid_nonces; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE oid_nonces (
    server_url character varying(2047) NOT NULL,
    "timestamp" integer NOT NULL,
    salt character(40) NOT NULL
);


--
-- Name: openid_discovered; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE openid_discovered (
    created timestamp without time zone,
    url text NOT NULL,
    services bytea,
    op_endpoint text,
    op_local text
);


--
-- Name: openid_nonces; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE openid_nonces (
    created timestamp without time zone,
    nonce text
);


--
-- Name: openid_sessions; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE openid_sessions (
    id integer NOT NULL,
    url text,
    assoc_handle text,
    expires timestamp without time zone,
    mac_key text
);


--
-- Name: openid_sessions_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE openid_sessions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: openid_sessions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE openid_sessions_id_seq OWNED BY openid_sessions.id;


--
-- Name: openid_whitelist; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE openid_whitelist (
    name text NOT NULL,
    trust_root text NOT NULL,
    created timestamp without time zone
);


--
-- Name: openids; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE openids (
    id text NOT NULL,
    name citext
);


SET default_with_oids = true;

--
-- Name: packages; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE packages (
    name text NOT NULL,
    stable_version text,
    normalized_name text,
    autohide boolean DEFAULT true,
    comments boolean DEFAULT true,
    bugtrack_url text,
    hosting_mode text DEFAULT 'pypi-explicit'::text NOT NULL,
    created timestamp without time zone DEFAULT now() NOT NULL,
    CONSTRAINT packages_valid_name CHECK ((name ~* '^([A-Z0-9]|[A-Z0-9][A-Z0-9._-]*[A-Z0-9])$'::text))
);


SET default_with_oids = false;

--
-- Name: ratings; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE ratings (
    name text NOT NULL,
    version text NOT NULL,
    user_name citext NOT NULL,
    date timestamp without time zone,
    rating integer,
    id integer NOT NULL
);


--
-- Name: ratings_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE ratings_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: ratings_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE ratings_id_seq OWNED BY ratings.id;


SET default_with_oids = true;

--
-- Name: rego_otk; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE rego_otk (
    name citext,
    otk text,
    date timestamp without time zone
);


--
-- Name: release_classifiers; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE release_classifiers (
    name text,
    version text,
    trove_id integer
);


SET default_with_oids = false;

--
-- Name: release_dependencies; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE release_dependencies (
    name text,
    version text,
    kind integer,
    specifier text
);


SET default_with_oids = true;

--
-- Name: release_files; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE release_files (
    name text,
    version text,
    python_version text,
    packagetype text,
    comment_text text,
    filename text,
    md5_digest text,
    downloads integer DEFAULT 0,
    upload_time timestamp without time zone
);


SET default_with_oids = false;

--
-- Name: release_requires_python; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE release_requires_python (
    name text,
    version text,
    specifier text
);


SET default_with_oids = true;

--
-- Name: release_urls; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE release_urls (
    name text,
    version text,
    url text,
    packagetype text
);


--
-- Name: releases; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE releases (
    name text NOT NULL,
    version text NOT NULL,
    author text,
    author_email text,
    maintainer text,
    maintainer_email text,
    home_page text,
    license text,
    summary text,
    description text,
    keywords text,
    platform text,
    download_url text,
    _pypi_ordering integer,
    _pypi_hidden boolean,
    description_html text,
    cheesecake_installability_id integer,
    cheesecake_documentation_id integer,
    cheesecake_code_kwalitee_id integer,
    requires_python text,
    description_from_readme boolean,
    created timestamp without time zone DEFAULT now() NOT NULL
);


--
-- Name: roles; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE roles (
    role_name text,
    user_name citext,
    package_name text
);


SET default_with_oids = false;

--
-- Name: sshkeys; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE sshkeys (
    id integer NOT NULL,
    name citext,
    key text
);


--
-- Name: sshkeys_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE sshkeys_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: sshkeys_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE sshkeys_id_seq OWNED BY sshkeys.id;


SET default_with_oids = true;

--
-- Name: timestamps; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE timestamps (
    name text NOT NULL,
    value timestamp without time zone
);


--
-- Name: trove_classifiers; Type: TABLE; Schema: public; Owner: -; Tablespace: 
--

CREATE TABLE trove_classifiers (
    id integer NOT NULL,
    classifier text,
    l2 integer,
    l3 integer,
    l4 integer,
    l5 integer
);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY accounts_email ALTER COLUMN id SET DEFAULT nextval('accounts_email_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY accounts_gpgkey ALTER COLUMN id SET DEFAULT nextval('accounts_gpgkey_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY accounts_user ALTER COLUMN id SET DEFAULT nextval('accounts_user_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY cheesecake_main_indices ALTER COLUMN id SET DEFAULT nextval('cheesecake_main_indices_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY comments ALTER COLUMN id SET DEFAULT nextval('comments_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY description_urls ALTER COLUMN id SET DEFAULT nextval('description_urls_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY journals ALTER COLUMN id SET DEFAULT nextval('journals_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY openid_sessions ALTER COLUMN id SET DEFAULT nextval('openid_sessions_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY ratings ALTER COLUMN id SET DEFAULT nextval('ratings_id_seq'::regclass);


--
-- Name: id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY sshkeys ALTER COLUMN id SET DEFAULT nextval('sshkeys_id_seq'::regclass);


--
-- Name: accounts_email_email_key; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY accounts_email
    ADD CONSTRAINT accounts_email_email_key UNIQUE (email);


--
-- Name: accounts_email_pkey; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY accounts_email
    ADD CONSTRAINT accounts_email_pkey PRIMARY KEY (id);


--
-- Name: accounts_gpgkey_key_id_key; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY accounts_gpgkey
    ADD CONSTRAINT accounts_gpgkey_key_id_key UNIQUE (key_id);


--
-- Name: accounts_gpgkey_pkey; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY accounts_gpgkey
    ADD CONSTRAINT accounts_gpgkey_pkey PRIMARY KEY (id);


--
-- Name: accounts_user_pkey; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY accounts_user
    ADD CONSTRAINT accounts_user_pkey PRIMARY KEY (id);


--
-- Name: accounts_user_username_key; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY accounts_user
    ADD CONSTRAINT accounts_user_username_key UNIQUE (username);


--
-- Name: browse_tally_pkey; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY browse_tally
    ADD CONSTRAINT browse_tally_pkey PRIMARY KEY (trove_id);


--
-- Name: cheesecake_main_indices_pkey; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY cheesecake_main_indices
    ADD CONSTRAINT cheesecake_main_indices_pkey PRIMARY KEY (id);


--
-- Name: cheesecake_subindices_pkey; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY cheesecake_subindices
    ADD CONSTRAINT cheesecake_subindices_pkey PRIMARY KEY (main_index_id, name);


--
-- Name: comments_pkey; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY comments
    ADD CONSTRAINT comments_pkey PRIMARY KEY (id);


--
-- Name: cookies_pkey; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY cookies
    ADD CONSTRAINT cookies_pkey PRIMARY KEY (cookie);


--
-- Name: csrf_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY csrf_tokens
    ADD CONSTRAINT csrf_tokens_pkey PRIMARY KEY (name);


--
-- Name: description_urls_pkey; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY description_urls
    ADD CONSTRAINT description_urls_pkey PRIMARY KEY (id);


--
-- Name: mirrors_pkey; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY mirrors
    ADD CONSTRAINT mirrors_pkey PRIMARY KEY (ip);


--
-- Name: oauth_access_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY oauth_access_tokens
    ADD CONSTRAINT oauth_access_tokens_pkey PRIMARY KEY (token);


--
-- Name: oauth_consumers_pkey; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY oauth_consumers
    ADD CONSTRAINT oauth_consumers_pkey PRIMARY KEY (consumer);


--
-- Name: oauth_request_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY oauth_request_tokens
    ADD CONSTRAINT oauth_request_tokens_pkey PRIMARY KEY (token);


--
-- Name: oid_associations_pkey; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY oid_associations
    ADD CONSTRAINT oid_associations_pkey PRIMARY KEY (server_url, handle);


--
-- Name: oid_nonces_pkey; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY oid_nonces
    ADD CONSTRAINT oid_nonces_pkey PRIMARY KEY (server_url, "timestamp", salt);


--
-- Name: openid_discovered_pkey; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY openid_discovered
    ADD CONSTRAINT openid_discovered_pkey PRIMARY KEY (url);


--
-- Name: openid_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY openid_sessions
    ADD CONSTRAINT openid_sessions_pkey PRIMARY KEY (id);


--
-- Name: openid_whitelist_pkey; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY openid_whitelist
    ADD CONSTRAINT openid_whitelist_pkey PRIMARY KEY (name, trust_root);


--
-- Name: openids_pkey; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY openids
    ADD CONSTRAINT openids_pkey PRIMARY KEY (id);


--
-- Name: packages_pkey; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY packages
    ADD CONSTRAINT packages_pkey PRIMARY KEY (name);


--
-- Name: ratings_id_key; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY ratings
    ADD CONSTRAINT ratings_id_key UNIQUE (id);


--
-- Name: ratings_name_key; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY ratings
    ADD CONSTRAINT ratings_name_key UNIQUE (name, version, user_name);


--
-- Name: ratings_pkey; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY ratings
    ADD CONSTRAINT ratings_pkey PRIMARY KEY (id);


--
-- Name: rego_otk_unique; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY rego_otk
    ADD CONSTRAINT rego_otk_unique UNIQUE (otk);


--
-- Name: release_files_filename_key; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY release_files
    ADD CONSTRAINT release_files_filename_key UNIQUE (filename);


--
-- Name: release_files_md5_digest_key; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY release_files
    ADD CONSTRAINT release_files_md5_digest_key UNIQUE (md5_digest);


--
-- Name: releases_pkey; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY releases
    ADD CONSTRAINT releases_pkey PRIMARY KEY (name, version);


--
-- Name: sshkeys_pkey; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY sshkeys
    ADD CONSTRAINT sshkeys_pkey PRIMARY KEY (id);


--
-- Name: timestamps_pkey; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY timestamps
    ADD CONSTRAINT timestamps_pkey PRIMARY KEY (name);


--
-- Name: trove_classifiers_classifier_key; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY trove_classifiers
    ADD CONSTRAINT trove_classifiers_classifier_key UNIQUE (classifier);


--
-- Name: trove_classifiers_pkey; Type: CONSTRAINT; Schema: public; Owner: -; Tablespace: 
--

ALTER TABLE ONLY trove_classifiers
    ADD CONSTRAINT trove_classifiers_pkey PRIMARY KEY (id);


--
-- Name: accounts_email_email_like; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX accounts_email_email_like ON accounts_email USING btree (email varchar_pattern_ops);


--
-- Name: accounts_email_user_id; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX accounts_email_user_id ON accounts_email USING btree (user_id);


--
-- Name: accounts_gpgkey_user_id; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX accounts_gpgkey_user_id ON accounts_gpgkey USING btree (user_id);


--
-- Name: cookies_last_seen; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX cookies_last_seen ON cookies USING btree (last_seen);


--
-- Name: description_urls_name_idx; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX description_urls_name_idx ON description_urls USING btree (name);


--
-- Name: description_urls_name_version_idx; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX description_urls_name_version_idx ON description_urls USING btree (name, version);


--
-- Name: journals_changelog; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX journals_changelog ON journals USING btree (submitted_date, name, version, action);


--
-- Name: journals_latest_releases; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX journals_latest_releases ON journals USING btree (submitted_date, name, version) WHERE ((version IS NOT NULL) AND (action = 'new release'::text));


--
-- Name: journals_name_idx; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX journals_name_idx ON journals USING btree (name);


--
-- Name: journals_version_idx; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX journals_version_idx ON journals USING btree (version);


--
-- Name: openid_nonces_created; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX openid_nonces_created ON openid_nonces USING btree (created);


--
-- Name: openid_nonces_nonce; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX openid_nonces_nonce ON openid_nonces USING btree (nonce);


--
-- Name: rating_name_version; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX rating_name_version ON ratings USING btree (name, version);


--
-- Name: rego_otk_name_idx; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX rego_otk_name_idx ON rego_otk USING btree (name);


--
-- Name: rego_otk_otk_idx; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX rego_otk_otk_idx ON rego_otk USING btree (otk);


--
-- Name: rel_class_name_idx; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX rel_class_name_idx ON release_classifiers USING btree (name);


--
-- Name: rel_class_name_version_idx; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX rel_class_name_version_idx ON release_classifiers USING btree (name, version);


--
-- Name: rel_class_trove_id_idx; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX rel_class_trove_id_idx ON release_classifiers USING btree (trove_id);


--
-- Name: rel_class_version_id_idx; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX rel_class_version_id_idx ON release_classifiers USING btree (version);


--
-- Name: rel_dep_name_idx; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX rel_dep_name_idx ON release_dependencies USING btree (name);


--
-- Name: rel_dep_name_version_idx; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX rel_dep_name_version_idx ON release_dependencies USING btree (name, version);


--
-- Name: rel_dep_name_version_kind_idx; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX rel_dep_name_version_kind_idx ON release_dependencies USING btree (name, version, kind);


--
-- Name: rel_req_python_name_idx; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX rel_req_python_name_idx ON release_requires_python USING btree (name);


--
-- Name: rel_req_python_name_version_idx; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX rel_req_python_name_version_idx ON release_requires_python USING btree (name, version);


--
-- Name: rel_req_python_version_id_idx; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX rel_req_python_version_id_idx ON release_requires_python USING btree (version);


--
-- Name: release_files_name_idx; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX release_files_name_idx ON release_files USING btree (name);


--
-- Name: release_files_name_version_idx; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX release_files_name_version_idx ON release_files USING btree (name, version);


--
-- Name: release_files_packagetype_idx; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX release_files_packagetype_idx ON release_files USING btree (packagetype);


--
-- Name: release_files_version_idx; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX release_files_version_idx ON release_files USING btree (version);


--
-- Name: release_name_idx; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX release_name_idx ON releases USING btree (name);


--
-- Name: release_pypi_hidden_idx; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX release_pypi_hidden_idx ON releases USING btree (_pypi_hidden);


--
-- Name: release_urls_name_idx; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX release_urls_name_idx ON release_urls USING btree (name);


--
-- Name: release_urls_packagetype_idx; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX release_urls_packagetype_idx ON release_urls USING btree (packagetype);


--
-- Name: release_urls_version_idx; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX release_urls_version_idx ON release_urls USING btree (version);


--
-- Name: release_version_idx; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX release_version_idx ON releases USING btree (version);


--
-- Name: roles_pack_name_idx; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX roles_pack_name_idx ON roles USING btree (package_name);


--
-- Name: roles_user_name_idx; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX roles_user_name_idx ON roles USING btree (user_name);


--
-- Name: sshkeys_name; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX sshkeys_name ON sshkeys USING btree (name);


--
-- Name: trove_class_class_idx; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX trove_class_class_idx ON trove_classifiers USING btree (classifier);


--
-- Name: trove_class_id_idx; Type: INDEX; Schema: public; Owner: -; Tablespace: 
--

CREATE INDEX trove_class_id_idx ON trove_classifiers USING btree (id);


--
-- Name: $1; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY release_classifiers
    ADD CONSTRAINT "$1" FOREIGN KEY (trove_id) REFERENCES trove_classifiers(id);


--
-- Name: $1; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY cheesecake_subindices
    ADD CONSTRAINT "$1" FOREIGN KEY (main_index_id) REFERENCES cheesecake_main_indices(id);


--
-- Name: $2; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY releases
    ADD CONSTRAINT "$2" FOREIGN KEY (cheesecake_installability_id) REFERENCES cheesecake_main_indices(id);


--
-- Name: $3; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY releases
    ADD CONSTRAINT "$3" FOREIGN KEY (cheesecake_documentation_id) REFERENCES cheesecake_main_indices(id);


--
-- Name: $4; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY releases
    ADD CONSTRAINT "$4" FOREIGN KEY (cheesecake_code_kwalitee_id) REFERENCES cheesecake_main_indices(id);


--
-- Name: comments_in_reply_to_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY comments
    ADD CONSTRAINT comments_in_reply_to_fkey FOREIGN KEY (in_reply_to) REFERENCES comments(id) ON DELETE CASCADE;


--
-- Name: comments_journal_name_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY comments_journal
    ADD CONSTRAINT comments_journal_name_fkey FOREIGN KEY (name, version) REFERENCES releases(name, version) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: comments_journal_submitted_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY comments_journal
    ADD CONSTRAINT comments_journal_submitted_by_fkey FOREIGN KEY (submitted_by) REFERENCES accounts_user(username) ON DELETE CASCADE;


--
-- Name: comments_rating_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY comments
    ADD CONSTRAINT comments_rating_fkey FOREIGN KEY (rating) REFERENCES ratings(id) ON DELETE CASCADE;


--
-- Name: comments_user_name_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY comments
    ADD CONSTRAINT comments_user_name_fkey FOREIGN KEY (user_name) REFERENCES accounts_user(username) ON DELETE CASCADE;


--
-- Name: cookies_name_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY cookies
    ADD CONSTRAINT cookies_name_fkey FOREIGN KEY (name) REFERENCES accounts_user(username) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: csrf_tokens_name_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY csrf_tokens
    ADD CONSTRAINT csrf_tokens_name_fkey FOREIGN KEY (name) REFERENCES accounts_user(username) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: description_urls_name_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY description_urls
    ADD CONSTRAINT description_urls_name_fkey FOREIGN KEY (name, version) REFERENCES releases(name, version) ON UPDATE CASCADE;


--
-- Name: journals_submitted_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY journals
    ADD CONSTRAINT journals_submitted_by_fkey FOREIGN KEY (submitted_by) REFERENCES accounts_user(username) ON UPDATE CASCADE;


--
-- Name: mirrors_user_name_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY mirrors
    ADD CONSTRAINT mirrors_user_name_fkey FOREIGN KEY (user_name) REFERENCES accounts_user(username);


--
-- Name: oauth_access_tokens_user_name_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY oauth_access_tokens
    ADD CONSTRAINT oauth_access_tokens_user_name_fkey FOREIGN KEY (user_name) REFERENCES accounts_user(username) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: oauth_consumers_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY oauth_consumers
    ADD CONSTRAINT oauth_consumers_created_by_fkey FOREIGN KEY (created_by) REFERENCES accounts_user(username) ON UPDATE CASCADE;


--
-- Name: oauth_request_tokens_user_name_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY oauth_request_tokens
    ADD CONSTRAINT oauth_request_tokens_user_name_fkey FOREIGN KEY (user_name) REFERENCES accounts_user(username) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: openids_name_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY openids
    ADD CONSTRAINT openids_name_fkey FOREIGN KEY (name) REFERENCES accounts_user(username) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: ratings_name_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY ratings
    ADD CONSTRAINT ratings_name_fkey FOREIGN KEY (name, version) REFERENCES releases(name, version) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: ratings_user_name_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY ratings
    ADD CONSTRAINT ratings_user_name_fkey FOREIGN KEY (user_name) REFERENCES accounts_user(username) ON DELETE CASCADE;


--
-- Name: rego_otk_name_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY rego_otk
    ADD CONSTRAINT rego_otk_name_fkey FOREIGN KEY (name) REFERENCES accounts_user(username) ON DELETE CASCADE;


--
-- Name: release_classifiers_name_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY release_classifiers
    ADD CONSTRAINT release_classifiers_name_fkey FOREIGN KEY (name, version) REFERENCES releases(name, version) ON UPDATE CASCADE;


--
-- Name: release_dependencies_name_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY release_dependencies
    ADD CONSTRAINT release_dependencies_name_fkey FOREIGN KEY (name, version) REFERENCES releases(name, version) ON UPDATE CASCADE;


--
-- Name: release_files_name_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY release_files
    ADD CONSTRAINT release_files_name_fkey FOREIGN KEY (name, version) REFERENCES releases(name, version) ON UPDATE CASCADE;


--
-- Name: release_requires_python_name_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY release_requires_python
    ADD CONSTRAINT release_requires_python_name_fkey FOREIGN KEY (name, version) REFERENCES releases(name, version) ON UPDATE CASCADE;


--
-- Name: release_urls_name_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY release_urls
    ADD CONSTRAINT release_urls_name_fkey FOREIGN KEY (name, version) REFERENCES releases(name, version) ON UPDATE CASCADE;


--
-- Name: releases_name_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY releases
    ADD CONSTRAINT releases_name_fkey FOREIGN KEY (name) REFERENCES packages(name) ON UPDATE CASCADE;


--
-- Name: roles_package_name_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY roles
    ADD CONSTRAINT roles_package_name_fkey FOREIGN KEY (package_name) REFERENCES packages(name) ON UPDATE CASCADE;


--
-- Name: roles_user_name_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY roles
    ADD CONSTRAINT roles_user_name_fkey FOREIGN KEY (user_name) REFERENCES accounts_user(username) ON UPDATE CASCADE;


--
-- Name: sshkeys_name_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY sshkeys
    ADD CONSTRAINT sshkeys_name_fkey FOREIGN KEY (name) REFERENCES accounts_user(username) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: user_id_refs_id_22cd5328; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY accounts_email
    ADD CONSTRAINT user_id_refs_id_22cd5328 FOREIGN KEY (user_id) REFERENCES accounts_user(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: user_id_refs_id_54e87d75; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY accounts_gpgkey
    ADD CONSTRAINT user_id_refs_id_54e87d75 FOREIGN KEY (user_id) REFERENCES accounts_user(id) DEFERRABLE INITIALLY DEFERRED;


--
-- Name: public; Type: ACL; Schema: -; Owner: -
--

REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM postgres;
GRANT ALL ON SCHEMA public TO postgres;
GRANT ALL ON SCHEMA public TO PUBLIC;


--
-- PostgreSQL database dump complete
--

--
-- PostgreSQL database dump
--

SET statement_timeout = 0;
SET lock_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET check_function_bodies = false;
SET client_min_messages = warning;

SET search_path = public, pg_catalog;

--
-- Data for Name: timestamps; Type: TABLE DATA; Schema: public; Owner: -
--

COPY timestamps (name, value) FROM stdin;
browse_tally	1970-01-01 00:00:00.000000
\.


--
-- PostgreSQL database dump complete
--

--
-- PostgreSQL database dump
--

SET statement_timeout = 0;
SET lock_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET check_function_bodies = false;
SET client_min_messages = warning;

SET search_path = public, pg_catalog;

--
-- Data for Name: trove_classifiers; Type: TABLE DATA; Schema: public; Owner: -
--

COPY trove_classifiers (id, classifier, l2, l3, l4, l5) FROM stdin;
457	Topic :: System :: Installation/Setup	439	457	0	0
458	Topic :: System :: Logging	439	458	0	0
459	Topic :: System :: Monitoring	439	459	0	0
460	Topic :: System :: Networking	439	460	0	0
461	Topic :: System :: Networking :: Firewalls	439	460	461	0
462	Topic :: System :: Networking :: Monitoring	439	460	462	0
463	Topic :: System :: Networking :: Monitoring :: Hardware Watchdog	439	460	462	463
464	Topic :: System :: Networking :: Time Synchronization	439	460	464	0
465	Topic :: System :: Operating System	439	465	0	0
466	Topic :: System :: Operating System Kernels	439	466	0	0
467	Topic :: System :: Operating System Kernels :: BSD	439	466	467	0
468	Topic :: System :: Operating System Kernels :: GNU Hurd	439	466	468	0
469	Topic :: System :: Operating System Kernels :: Linux	439	466	469	0
470	Topic :: System :: Power (UPS)	439	470	0	0
471	Topic :: System :: Recovery Tools	439	471	0	0
472	Topic :: System :: Shells	439	472	0	0
473	Topic :: System :: Software Distribution	439	473	0	0
474	Topic :: System :: Systems Administration	439	474	0	0
475	Topic :: System :: Systems Administration :: Authentication/Directory	439	474	475	0
476	Topic :: System :: Systems Administration :: Authentication/Directory :: LDAP	439	474	475	476
477	Topic :: System :: Systems Administration :: Authentication/Directory :: NIS	439	474	475	477
478	Topic :: System :: System Shells	439	478	0	0
479	Topic :: Terminals	479	0	0	0
480	Topic :: Terminals :: Serial	479	480	0	0
481	Topic :: Terminals :: Telnet	479	481	0	0
482	Topic :: Terminals :: Terminal Emulators/X Terminals	479	482	0	0
483	Topic :: Text Editors	483	0	0	0
484	Topic :: Text Editors :: Documentation	483	484	0	0
485	Topic :: Text Editors :: Emacs	483	485	0	0
486	Topic :: Text Editors :: Integrated Development Environments (IDE)	483	486	0	0
487	Topic :: Text Editors :: Text Processing	483	487	0	0
488	Topic :: Text Editors :: Word Processors	483	488	0	0
489	Topic :: Text Processing	489	0	0	0
490	Topic :: Text Processing :: Filters	489	490	0	0
491	Topic :: Text Processing :: Fonts	489	491	0	0
492	Topic :: Text Processing :: General	489	492	0	0
493	Topic :: Text Processing :: Indexing	489	493	0	0
494	Topic :: Text Processing :: Linguistic	489	494	0	0
495	Topic :: Text Processing :: Markup	489	495	0	0
496	Topic :: Text Processing :: Markup :: HTML	489	495	496	0
497	Topic :: Text Processing :: Markup :: LaTeX	489	495	497	0
498	Topic :: Text Processing :: Markup :: SGML	489	495	498	0
499	Topic :: Text Processing :: Markup :: VRML	489	495	499	0
500	Topic :: Text Processing :: Markup :: XML	489	495	500	0
501	Topic :: Utilities	501	0	0	0
502	Framework :: Paste	502	0	0	0
503	Framework :: TurboGears	503	0	0	0
504	Framework :: TurboGears :: Widgets	503	504	0	0
511	Topic :: Scientific/Engineering :: Atmospheric Science	385	511	0	0
506	Topic :: Internet :: WWW/HTTP :: WSGI	319	326	506	0
507	Topic :: Internet :: WWW/HTTP :: WSGI :: Application	319	326	506	507
508	Topic :: Internet :: WWW/HTTP :: WSGI :: Server	319	326	506	508
509	Topic :: Internet :: WWW/HTTP :: WSGI :: Middleware	319	326	506	509
510	Framework :: TurboGears :: Applications	503	510	0	0
512	Framework :: Buildout	512	0	0	0
513	Framework :: ZODB	513	0	0	0
514	Framework :: Zope2	514	0	0	0
515	Framework :: Zope3	515	0	0	0
516	Framework :: Trac	516	0	0	0
517	Environment :: Web Environment :: Buffet	21	517	0	0
518	Framework :: Plone	518	0	0	0
519	Framework :: Chandler	519	0	0	0
520	Framework :: IDLE	520	0	0	0
376	Topic :: Office/Business :: Financial :: Point-Of-Sale	372	373	376	0
377	Topic :: Office/Business :: Financial :: Spreadsheet	372	373	377	0
378	Topic :: Office/Business :: Groupware	372	378	0	0
379	Topic :: Office/Business :: News/Diary	372	379	0	0
380	Topic :: Office/Business :: Office Suites	372	380	0	0
381	Topic :: Office/Business :: Scheduling	372	381	0	0
382	Topic :: Other/Nonlisted Topic	382	0	0	0
383	Topic :: Printing	383	0	0	0
384	Topic :: Religion	384	0	0	0
385	Topic :: Scientific/Engineering	385	0	0	0
386	Topic :: Scientific/Engineering :: Artificial Intelligence	385	386	0	0
387	Topic :: Scientific/Engineering :: Astronomy	385	387	0	0
388	Topic :: Scientific/Engineering :: Bio-Informatics	385	388	0	0
389	Topic :: Scientific/Engineering :: Chemistry	385	389	0	0
390	Topic :: Scientific/Engineering :: Electronic Design Automation (EDA)	385	390	0	0
391	Topic :: Scientific/Engineering :: GIS	385	391	0	0
392	Topic :: Scientific/Engineering :: Human Machine Interfaces	385	392	0	0
393	Topic :: Scientific/Engineering :: Image Recognition	385	393	0	0
394	Topic :: Scientific/Engineering :: Information Analysis	385	394	0	0
395	Topic :: Scientific/Engineering :: Interface Engine/Protocol Translator	385	395	0	0
397	Topic :: Scientific/Engineering :: Medical Science Apps.	385	397	0	0
398	Topic :: Scientific/Engineering :: Physics	385	398	0	0
399	Topic :: Scientific/Engineering :: Visualization	385	399	0	0
400	Topic :: Security	400	0	0	0
401	Topic :: Security :: Cryptography	400	401	0	0
402	Topic :: Sociology	402	0	0	0
403	Topic :: Sociology :: Genealogy	402	403	0	0
404	Topic :: Sociology :: History	402	404	0	0
405	Topic :: Software Development	405	0	0	0
406	Topic :: Software Development :: Assemblers	405	406	0	0
407	Topic :: Software Development :: Bug Tracking	405	407	0	0
408	Topic :: Software Development :: Build Tools	405	408	0	0
409	Topic :: Software Development :: Code Generators	405	409	0	0
410	Topic :: Software Development :: Compilers	405	410	0	0
411	Topic :: Software Development :: Debuggers	405	411	0	0
412	Topic :: Software Development :: Disassemblers	405	412	0	0
413	Topic :: Software Development :: Documentation	405	413	0	0
414	Topic :: Software Development :: Embedded Systems	405	414	0	0
415	Topic :: Software Development :: Internationalization	405	415	0	0
416	Topic :: Software Development :: Interpreters	405	416	0	0
417	Topic :: Software Development :: Libraries	405	417	0	0
418	Topic :: Software Development :: Libraries :: Application Frameworks	405	417	418	0
419	Topic :: Software Development :: Libraries :: Java Libraries	405	417	419	0
420	Topic :: Software Development :: Libraries :: Perl Modules	405	417	420	0
421	Topic :: Software Development :: Libraries :: PHP Classes	405	417	421	0
422	Topic :: Software Development :: Libraries :: Pike Modules	405	417	422	0
423	Topic :: Software Development :: Libraries :: Python Modules	405	417	423	0
424	Topic :: Software Development :: Libraries :: Ruby Modules	405	417	424	0
425	Topic :: Software Development :: Libraries :: Tcl Extensions	405	417	425	0
426	Topic :: Software Development :: Localization	405	426	0	0
427	Topic :: Software Development :: Object Brokering	405	427	0	0
428	Topic :: Software Development :: Object Brokering :: CORBA	405	427	428	0
429	Topic :: Software Development :: Pre-processors	405	429	0	0
430	Topic :: Software Development :: Quality Assurance	405	430	0	0
431	Topic :: Software Development :: Testing	405	431	0	0
432	Topic :: Software Development :: Testing :: Traffic Generation	405	431	432	0
433	Topic :: Software Development :: User Interfaces	405	433	0	0
434	Topic :: Software Development :: Version Control	405	434	0	0
435	Topic :: Software Development :: Version Control :: CVS	405	434	435	0
436	Topic :: Software Development :: Version Control :: RCS	405	434	436	0
437	Topic :: Software Development :: Version Control :: SCCS	405	434	437	0
438	Topic :: Software Development :: Widget Sets	405	438	0	0
439	Topic :: System	439	0	0	0
440	Topic :: System :: Archiving	439	440	0	0
441	Topic :: System :: Archiving :: Backup	439	440	441	0
442	Topic :: System :: Archiving :: Compression	439	440	442	0
443	Topic :: System :: Archiving :: Mirroring	439	440	443	0
444	Topic :: System :: Archiving :: Packaging	439	440	444	0
445	Topic :: System :: Benchmark	439	445	0	0
446	Topic :: System :: Boot	439	446	0	0
447	Topic :: System :: Boot :: Init	439	446	447	0
448	Topic :: System :: Clustering	439	448	0	0
449	Topic :: System :: Console Fonts	439	449	0	0
450	Topic :: System :: Distributed Computing	439	450	0	0
451	Topic :: System :: Emulators	439	451	0	0
452	Topic :: System :: Filesystems	439	452	0	0
453	Topic :: System :: Hardware	439	453	0	0
454	Topic :: System :: Hardware :: Hardware Drivers	439	453	454	0
455	Topic :: System :: Hardware :: Mainframes	439	453	455	0
456	Topic :: System :: Hardware :: Symmetric Multi-processing	439	453	456	0
297	Topic :: Desktop Environment :: Window Managers :: Window Maker	259	269	297	0
298	Topic :: Desktop Environment :: Window Managers :: Window Maker :: Applets	259	269	297	298
299	Topic :: Desktop Environment :: Window Managers :: Window Maker :: Themes	259	269	297	299
300	Topic :: Desktop Environment :: Window Managers :: XFCE	259	269	300	0
301	Topic :: Desktop Environment :: Window Managers :: XFCE :: Themes	259	269	300	301
303	Topic :: Education	303	0	0	0
304	Topic :: Education :: Computer Aided Instruction (CAI)	303	304	0	0
305	Topic :: Education :: Testing	303	305	0	0
306	Topic :: Games/Entertainment	306	0	0	0
307	Topic :: Games/Entertainment :: Arcade	306	307	0	0
308	Topic :: Games/Entertainment :: Board Games	306	308	0	0
309	Topic :: Games/Entertainment :: First Person Shooters	306	309	0	0
310	Topic :: Games/Entertainment :: Fortune Cookies	306	310	0	0
311	Topic :: Games/Entertainment :: Multi-User Dungeons (MUD)	306	311	0	0
312	Topic :: Games/Entertainment :: Puzzle Games	306	312	0	0
313	Topic :: Games/Entertainment :: Real Time Strategy	306	313	0	0
314	Topic :: Games/Entertainment :: Role-Playing	306	314	0	0
315	Topic :: Games/Entertainment :: Side-Scrolling/Arcade Games	306	315	0	0
316	Topic :: Games/Entertainment :: Simulation	306	316	0	0
317	Topic :: Games/Entertainment :: Turn Based Strategy	306	317	0	0
318	Topic :: Home Automation	318	0	0	0
319	Topic :: Internet	319	0	0	0
320	Topic :: Internet :: File Transfer Protocol (FTP)	319	320	0	0
321	Topic :: Internet :: Finger	319	321	0	0
322	Topic :: Internet :: Log Analysis	319	322	0	0
323	Topic :: Internet :: Name Service (DNS)	319	323	0	0
324	Topic :: Internet :: Proxy Servers	319	324	0	0
325	Topic :: Internet :: WAP	319	325	0	0
326	Topic :: Internet :: WWW/HTTP	319	326	0	0
327	Topic :: Internet :: WWW/HTTP :: Browsers	319	326	327	0
328	Topic :: Internet :: WWW/HTTP :: Dynamic Content	319	326	328	0
329	Topic :: Internet :: WWW/HTTP :: Dynamic Content :: CGI Tools/Libraries	319	326	328	329
330	Topic :: Internet :: WWW/HTTP :: Dynamic Content :: Message Boards	319	326	328	330
331	Topic :: Internet :: WWW/HTTP :: Dynamic Content :: News/Diary	319	326	328	331
332	Topic :: Internet :: WWW/HTTP :: Dynamic Content :: Page Counters	319	326	328	332
333	Topic :: Internet :: WWW/HTTP :: HTTP Servers	319	326	333	0
334	Topic :: Internet :: WWW/HTTP :: Indexing/Search	319	326	334	0
335	Topic :: Internet :: WWW/HTTP :: Site Management	319	326	335	0
336	Topic :: Internet :: WWW/HTTP :: Site Management :: Link Checking	319	326	335	336
337	Topic :: Internet :: Z39.50	319	337	0	0
338	Topic :: Multimedia	338	0	0	0
339	Topic :: Multimedia :: Graphics	338	339	0	0
340	Topic :: Multimedia :: Graphics :: 3D Modeling	338	339	340	0
341	Topic :: Multimedia :: Graphics :: 3D Rendering	338	339	341	0
342	Topic :: Multimedia :: Graphics :: Capture	338	339	342	0
343	Topic :: Multimedia :: Graphics :: Capture :: Digital Camera	338	339	342	343
344	Topic :: Multimedia :: Graphics :: Capture :: Scanners	338	339	342	344
345	Topic :: Multimedia :: Graphics :: Capture :: Screen Capture	338	339	342	345
346	Topic :: Multimedia :: Graphics :: Editors	338	339	346	0
347	Topic :: Multimedia :: Graphics :: Editors :: Raster-Based	338	339	346	347
348	Topic :: Multimedia :: Graphics :: Editors :: Vector-Based	338	339	346	348
349	Topic :: Multimedia :: Graphics :: Graphics Conversion	338	339	349	0
350	Topic :: Multimedia :: Graphics :: Presentation	338	339	350	0
351	Topic :: Multimedia :: Graphics :: Viewers	338	339	351	0
352	Topic :: Multimedia :: Sound/Audio	338	352	0	0
353	Topic :: Multimedia :: Sound/Audio :: Analysis	338	352	353	0
354	Topic :: Multimedia :: Sound/Audio :: Capture/Recording	338	352	354	0
355	Topic :: Multimedia :: Sound/Audio :: CD Audio	338	352	355	0
356	Topic :: Multimedia :: Sound/Audio :: CD Audio :: CD Playing	338	352	355	356
357	Topic :: Multimedia :: Sound/Audio :: CD Audio :: CD Ripping	338	352	355	357
358	Topic :: Multimedia :: Sound/Audio :: CD Audio :: CD Writing	338	352	355	358
359	Topic :: Multimedia :: Sound/Audio :: Conversion	338	352	359	0
360	Topic :: Multimedia :: Sound/Audio :: Editors	338	352	360	0
361	Topic :: Multimedia :: Sound/Audio :: MIDI	338	352	361	0
362	Topic :: Multimedia :: Sound/Audio :: Mixers	338	352	362	0
363	Topic :: Multimedia :: Sound/Audio :: Players	338	352	363	0
364	Topic :: Multimedia :: Sound/Audio :: Players :: MP3	338	352	363	364
365	Topic :: Multimedia :: Sound/Audio :: Sound Synthesis	338	352	365	0
366	Topic :: Multimedia :: Sound/Audio :: Speech	338	352	366	0
367	Topic :: Multimedia :: Video	338	367	0	0
368	Topic :: Multimedia :: Video :: Capture	338	367	368	0
369	Topic :: Multimedia :: Video :: Conversion	338	367	369	0
370	Topic :: Multimedia :: Video :: Display	338	367	370	0
371	Topic :: Multimedia :: Video :: Non-Linear Editor	338	367	371	0
372	Topic :: Office/Business	372	0	0	0
373	Topic :: Office/Business :: Financial	372	373	0	0
374	Topic :: Office/Business :: Financial :: Accounting	372	373	374	0
375	Topic :: Office/Business :: Financial :: Investment	372	373	375	0
221	Programming Language :: SQL	221	0	0	0
222	Programming Language :: Tcl	222	0	0	0
223	Programming Language :: Unix Shell	223	0	0	0
224	Programming Language :: Visual Basic	224	0	0	0
225	Programming Language :: XBasic	225	0	0	0
226	Programming Language :: YACC	226	0	0	0
227	Programming Language :: Zope	227	0	0	0
228	Topic :: Adaptive Technologies	228	0	0	0
229	Topic :: Artistic Software	229	0	0	0
230	Topic :: Communications	230	0	0	0
231	Topic :: Communications :: BBS	230	231	0	0
232	Topic :: Communications :: Chat	230	232	0	0
233	Topic :: Communications :: Chat :: AOL Instant Messenger	230	232	233	0
234	Topic :: Communications :: Chat :: ICQ	230	232	234	0
235	Topic :: Communications :: Chat :: Internet Relay Chat	230	232	235	0
236	Topic :: Communications :: Chat :: Unix Talk	230	232	236	0
237	Topic :: Communications :: Conferencing	230	237	0	0
238	Topic :: Communications :: Email	230	238	0	0
239	Topic :: Communications :: Email :: Address Book	230	238	239	0
240	Topic :: Communications :: Email :: Email Clients (MUA)	230	238	240	0
241	Topic :: Communications :: Email :: Filters	230	238	241	0
242	Topic :: Communications :: Email :: Mailing List Servers	230	238	242	0
243	Topic :: Communications :: Email :: Mail Transport Agents	230	238	243	0
244	Topic :: Communications :: Email :: Post-Office	230	238	244	0
245	Topic :: Communications :: Email :: Post-Office :: IMAP	230	238	244	245
246	Topic :: Communications :: Email :: Post-Office :: POP3	230	238	244	246
247	Topic :: Communications :: Fax	230	247	0	0
248	Topic :: Communications :: FIDO	230	248	0	0
249	Topic :: Communications :: File Sharing	230	249	0	0
250	Topic :: Communications :: File Sharing :: Gnutella	230	249	250	0
40	Intended Audience :: Science/Research	40	0	0	0
251	Topic :: Communications :: File Sharing :: Napster	230	249	251	0
252	Topic :: Communications :: Ham Radio	230	252	0	0
253	Topic :: Communications :: Internet Phone	230	253	0	0
254	Topic :: Communications :: Telephony	230	254	0	0
255	Topic :: Communications :: Usenet News	230	255	0	0
256	Topic :: Database	256	0	0	0
257	Topic :: Database :: Database Engines/Servers	256	257	0	0
258	Topic :: Database :: Front-Ends	256	258	0	0
259	Topic :: Desktop Environment	259	0	0	0
260	Topic :: Desktop Environment :: File Managers	259	260	0	0
261	Topic :: Desktop Environment :: Gnome	259	261	0	0
262	Topic :: Desktop Environment :: GNUstep	259	262	0	0
263	Topic :: Desktop Environment :: K Desktop Environment (KDE)	259	263	0	0
264	Topic :: Desktop Environment :: K Desktop Environment (KDE) :: Themes	259	263	264	0
265	Topic :: Desktop Environment :: PicoGUI	259	265	0	0
266	Topic :: Desktop Environment :: PicoGUI :: Applications	259	265	266	0
267	Topic :: Desktop Environment :: PicoGUI :: Themes	259	265	267	0
268	Topic :: Desktop Environment :: Screen Savers	259	268	0	0
269	Topic :: Desktop Environment :: Window Managers	259	269	0	0
270	Topic :: Desktop Environment :: Window Managers :: Afterstep	259	269	270	0
271	Topic :: Desktop Environment :: Window Managers :: Afterstep :: Themes	259	269	270	271
272	Topic :: Desktop Environment :: Window Managers :: Applets	259	269	272	0
273	Topic :: Desktop Environment :: Window Managers :: Blackbox	259	269	273	0
274	Topic :: Desktop Environment :: Window Managers :: Blackbox :: Themes	259	269	273	274
275	Topic :: Desktop Environment :: Window Managers :: CTWM	259	269	275	0
276	Topic :: Desktop Environment :: Window Managers :: CTWM :: Themes	259	269	275	276
277	Topic :: Desktop Environment :: Window Managers :: Enlightenment	259	269	277	0
278	Topic :: Desktop Environment :: Window Managers :: Enlightenment :: Epplets	259	269	277	278
279	Topic :: Desktop Environment :: Window Managers :: Enlightenment :: Themes DR15	259	269	277	279
280	Topic :: Desktop Environment :: Window Managers :: Enlightenment :: Themes DR16	259	269	277	280
281	Topic :: Desktop Environment :: Window Managers :: Enlightenment :: Themes DR17	259	269	277	281
282	Topic :: Desktop Environment :: Window Managers :: Fluxbox	259	269	282	0
283	Topic :: Desktop Environment :: Window Managers :: Fluxbox :: Themes	259	269	282	283
284	Topic :: Desktop Environment :: Window Managers :: FVWM	259	269	284	0
285	Topic :: Desktop Environment :: Window Managers :: FVWM :: Themes	259	269	284	285
286	Topic :: Desktop Environment :: Window Managers :: IceWM	259	269	286	0
287	Topic :: Desktop Environment :: Window Managers :: IceWM :: Themes	259	269	286	287
288	Topic :: Desktop Environment :: Window Managers :: MetaCity	259	269	288	0
289	Topic :: Desktop Environment :: Window Managers :: MetaCity :: Themes	259	269	288	289
290	Topic :: Desktop Environment :: Window Managers :: Oroborus	259	269	290	0
291	Topic :: Desktop Environment :: Window Managers :: Oroborus :: Themes	259	269	290	291
292	Topic :: Desktop Environment :: Window Managers :: Sawfish	259	269	292	0
293	Topic :: Desktop Environment :: Window Managers :: Sawfish :: Themes 0.30	259	269	292	293
294	Topic :: Desktop Environment :: Window Managers :: Sawfish :: Themes pre-0.30	259	269	292	294
295	Topic :: Desktop Environment :: Window Managers :: Waimea	259	269	295	0
296	Topic :: Desktop Environment :: Window Managers :: Waimea :: Themes	259	269	295	296
130	Natural Language :: Romanian	130	0	0	0
131	Natural Language :: Russian	131	0	0	0
132	Natural Language :: Serbian	132	0	0	0
133	Natural Language :: Slovak	133	0	0	0
134	Natural Language :: Slovenian	134	0	0	0
135	Natural Language :: Spanish	135	0	0	0
136	Natural Language :: Swedish	136	0	0	0
137	Natural Language :: Tamil	137	0	0	0
138	Natural Language :: Telugu	138	0	0	0
139	Natural Language :: Thai	139	0	0	0
140	Natural Language :: Turkish	140	0	0	0
141	Natural Language :: Ukranian	141	0	0	0
142	Natural Language :: Urdu	142	0	0	0
143	Natural Language :: Vietnamese	143	0	0	0
144	Operating System :: BeOS	144	0	0	0
145	Operating System :: MacOS	145	0	0	0
146	Operating System :: MacOS :: MacOS 9	145	146	0	0
147	Operating System :: MacOS :: MacOS X	145	147	0	0
148	Operating System :: Microsoft	148	0	0	0
149	Operating System :: Microsoft :: MS-DOS	148	149	0	0
150	Operating System :: Microsoft :: Windows	148	150	0	0
151	Operating System :: Microsoft :: Windows :: Windows 3.1 or Earlier	148	150	151	0
152	Operating System :: Microsoft :: Windows :: Windows 95/98/2000	148	150	152	0
153	Operating System :: Microsoft :: Windows :: Windows CE	148	150	153	0
154	Operating System :: Microsoft :: Windows :: Windows NT/2000	148	150	154	0
155	Operating System :: OS/2	155	0	0	0
156	Operating System :: OS Independent	156	0	0	0
157	Operating System :: Other OS	157	0	0	0
158	Operating System :: PalmOS	158	0	0	0
159	Operating System :: PDA Systems	159	0	0	0
160	Operating System :: POSIX	160	0	0	0
161	Operating System :: POSIX :: AIX	160	161	0	0
162	Operating System :: POSIX :: BSD	160	162	0	0
163	Operating System :: POSIX :: BSD :: BSD/OS	160	162	163	0
164	Operating System :: POSIX :: BSD :: FreeBSD	160	162	164	0
165	Operating System :: POSIX :: BSD :: NetBSD	160	162	165	0
166	Operating System :: POSIX :: BSD :: OpenBSD	160	162	166	0
167	Operating System :: POSIX :: GNU Hurd	160	167	0	0
168	Operating System :: POSIX :: HP-UX	160	168	0	0
169	Operating System :: POSIX :: IRIX	160	169	0	0
170	Operating System :: POSIX :: Linux	160	170	0	0
171	Operating System :: POSIX :: Other	160	171	0	0
172	Operating System :: POSIX :: SCO	160	172	0	0
173	Operating System :: POSIX :: SunOS/Solaris	160	173	0	0
174	Operating System :: Unix	174	0	0	0
175	Programming Language :: Ada	175	0	0	0
176	Programming Language :: APL	176	0	0	0
177	Programming Language :: ASP	177	0	0	0
178	Programming Language :: Assembly	178	0	0	0
179	Programming Language :: Awk	179	0	0	0
180	Programming Language :: Basic	180	0	0	0
181	Programming Language :: C	181	0	0	0
182	Programming Language :: C#	182	0	0	0
183	Programming Language :: C++	183	0	0	0
184	Programming Language :: Cold Fusion	184	0	0	0
185	Programming Language :: Delphi/Kylix	185	0	0	0
186	Programming Language :: Dylan	186	0	0	0
187	Programming Language :: Eiffel	187	0	0	0
188	Programming Language :: Emacs-Lisp	188	0	0	0
189	Programming Language :: Erlang	189	0	0	0
190	Programming Language :: Euler	190	0	0	0
191	Programming Language :: Euphoria	191	0	0	0
192	Programming Language :: Forth	192	0	0	0
193	Programming Language :: Fortran	193	0	0	0
194	Programming Language :: Haskell	194	0	0	0
195	Programming Language :: Java	195	0	0	0
196	Programming Language :: JavaScript	196	0	0	0
197	Programming Language :: Lisp	197	0	0	0
198	Programming Language :: Logo	198	0	0	0
199	Programming Language :: ML	199	0	0	0
200	Programming Language :: Modula	200	0	0	0
201	Programming Language :: Objective C	201	0	0	0
202	Programming Language :: Object Pascal	202	0	0	0
203	Programming Language :: OCaml	203	0	0	0
204	Programming Language :: Other	204	0	0	0
205	Programming Language :: Other Scripting Engines	205	0	0	0
206	Programming Language :: Pascal	206	0	0	0
207	Programming Language :: Perl	207	0	0	0
208	Programming Language :: PHP	208	0	0	0
209	Programming Language :: Pike	209	0	0	0
210	Programming Language :: Pliant	210	0	0	0
211	Programming Language :: PL/SQL	211	0	0	0
212	Programming Language :: PROGRESS	212	0	0	0
213	Programming Language :: Prolog	213	0	0	0
214	Programming Language :: Python	214	0	0	0
215	Programming Language :: REBOL	215	0	0	0
216	Programming Language :: Rexx	216	0	0	0
217	Programming Language :: Ruby	217	0	0	0
218	Programming Language :: Scheme	218	0	0	0
219	Programming Language :: Simula	219	0	0	0
220	Programming Language :: Smalltalk	220	0	0	0
46	License :: Free For Educational Use	46	0	0	0
47	License :: Free For Home Use	47	0	0	0
48	License :: Free for non-commercial use	48	0	0	0
49	License :: Freely Distributable	49	0	0	0
50	License :: Free To Use But Restricted	50	0	0	0
51	License :: Freeware	51	0	0	0
52	License :: Netscape Public License (NPL)	52	0	0	0
53	License :: Nokia Open Source License (NOKOS)	53	0	0	0
54	License :: OSI Approved	54	0	0	0
55	License :: OSI Approved :: Academic Free License (AFL)	54	55	0	0
56	License :: OSI Approved :: Apache Software License	54	56	0	0
57	License :: OSI Approved :: Apple Public Source License	54	57	0	0
58	License :: OSI Approved :: Artistic License	54	58	0	0
59	License :: OSI Approved :: Attribution Assurance License	54	59	0	0
60	License :: OSI Approved :: BSD License	54	60	0	0
61	License :: OSI Approved :: Common Public License	54	61	0	0
62	License :: OSI Approved :: Eiffel Forum License	54	62	0	0
63	License :: OSI Approved :: GNU Free Documentation License (FDL)	54	63	0	0
64	License :: OSI Approved :: GNU General Public License (GPL)	54	64	0	0
65	License :: OSI Approved :: GNU Library or Lesser General Public License (LGPL)	54	65	0	0
66	License :: OSI Approved :: IBM Public License	54	66	0	0
67	License :: OSI Approved :: Intel Open Source License	54	67	0	0
68	License :: OSI Approved :: Jabber Open Source License	54	68	0	0
69	License :: OSI Approved :: MIT License	54	69	0	0
70	License :: OSI Approved :: MITRE Collaborative Virtual Workspace License (CVW)	54	70	0	0
71	License :: OSI Approved :: Motosoto License	54	71	0	0
72	License :: OSI Approved :: Mozilla Public License 1.0 (MPL)	54	72	0	0
73	License :: OSI Approved :: Mozilla Public License 1.1 (MPL 1.1)	54	73	0	0
74	License :: OSI Approved :: Nethack General Public License	54	74	0	0
75	License :: OSI Approved :: Nokia Open Source License	54	75	0	0
76	License :: OSI Approved :: Open Group Test Suite License	54	76	0	0
77	License :: OSI Approved :: Python License (CNRI Python License)	54	77	0	0
41	Intended Audience :: System Administrators	41	0	0	0
78	License :: OSI Approved :: Python Software Foundation License	54	78	0	0
79	License :: OSI Approved :: Qt Public License (QPL)	54	79	0	0
80	License :: OSI Approved :: Ricoh Source Code Public License	54	80	0	0
81	License :: OSI Approved :: Sleepycat License	54	81	0	0
82	License :: OSI Approved :: Sun Industry Standards Source License (SISSL)	54	82	0	0
83	License :: OSI Approved :: Sun Public License	54	83	0	0
84	License :: OSI Approved :: University of Illinois/NCSA Open Source License	54	84	0	0
85	License :: OSI Approved :: Vovida Software License 1.0	54	85	0	0
86	License :: OSI Approved :: W3C License	54	86	0	0
87	License :: OSI Approved :: X.Net License	54	87	0	0
88	License :: OSI Approved :: zlib/libpng License	54	88	0	0
89	License :: OSI Approved :: Zope Public License	54	89	0	0
90	License :: Other/Proprietary License	90	0	0	0
91	License :: Public Domain	91	0	0	0
92	Natural Language :: Afrikaans	92	0	0	0
93	Natural Language :: Arabic	93	0	0	0
94	Natural Language :: Bengali	94	0	0	0
95	Natural Language :: Bosnian	95	0	0	0
96	Natural Language :: Bulgarian	96	0	0	0
97	Natural Language :: Catalan	97	0	0	0
98	Natural Language :: Chinese (Simplified)	98	0	0	0
99	Natural Language :: Chinese (Traditional)	99	0	0	0
100	Natural Language :: Croatian	100	0	0	0
101	Natural Language :: Czech	101	0	0	0
102	Natural Language :: Danish	102	0	0	0
103	Natural Language :: Dutch	103	0	0	0
104	Natural Language :: English	104	0	0	0
105	Natural Language :: Esperanto	105	0	0	0
106	Natural Language :: Finnish	106	0	0	0
107	Natural Language :: French	107	0	0	0
108	Natural Language :: German	108	0	0	0
109	Natural Language :: Greek	109	0	0	0
110	Natural Language :: Hebrew	110	0	0	0
111	Natural Language :: Hindi	111	0	0	0
112	Natural Language :: Hungarian	112	0	0	0
113	Natural Language :: Icelandic	113	0	0	0
114	Natural Language :: Indonesian	114	0	0	0
115	Natural Language :: Italian	115	0	0	0
116	Natural Language :: Japanese	116	0	0	0
117	Natural Language :: Javanese	117	0	0	0
118	Natural Language :: Korean	118	0	0	0
119	Natural Language :: Latin	119	0	0	0
120	Natural Language :: Latvian	120	0	0	0
121	Natural Language :: Macedonian	121	0	0	0
122	Natural Language :: Malay	122	0	0	0
123	Natural Language :: Marathi	123	0	0	0
124	Natural Language :: Norwegian	124	0	0	0
125	Natural Language :: Panjabi	125	0	0	0
126	Natural Language :: Persian	126	0	0	0
127	Natural Language :: Polish	127	0	0	0
128	Natural Language :: Portuguese	128	0	0	0
129	Natural Language :: Portuguese (Brazilian)	129	0	0	0
302	Topic :: Documentation	302	0	0	0
1	Development Status :: 1 - Planning	1	0	0	0
2	Development Status :: 2 - Pre-Alpha	2	0	0	0
3	Development Status :: 3 - Alpha	3	0	0	0
4	Development Status :: 4 - Beta	4	0	0	0
5	Development Status :: 5 - Production/Stable	5	0	0	0
6	Development Status :: 6 - Mature	6	0	0	0
7	Development Status :: 7 - Inactive	7	0	0	0
8	Environment :: Console	8	0	0	0
9	Environment :: Console :: Framebuffer	8	9	0	0
10	Environment :: Console :: svgalib	8	10	0	0
11	Environment :: Console :: Curses	8	11	0	0
12	Environment :: Console :: Newt	8	12	0	0
13	Environment :: MacOS X	13	0	0	0
14	Environment :: MacOS X :: Aqua	13	14	0	0
15	Environment :: MacOS X :: Carbon	13	15	0	0
16	Environment :: MacOS X :: Cocoa	13	16	0	0
17	Environment :: Handhelds/PDA's	17	0	0	0
18	Environment :: No Input/Output (Daemon)	18	0	0	0
19	Environment :: Plugins	19	0	0	0
20	Environment :: Other Environment	20	0	0	0
21	Environment :: Web Environment	21	0	0	0
22	Environment :: Web Environment :: Mozilla	21	22	0	0
23	Environment :: Win32 (MS Windows)	23	0	0	0
24	Environment :: X11 Applications	24	0	0	0
25	Environment :: X11 Applications :: Gnome	24	25	0	0
26	Environment :: X11 Applications :: GTK	24	26	0	0
27	Environment :: X11 Applications :: KDE	24	27	0	0
28	Environment :: X11 Applications :: Qt	24	28	0	0
29	Intended Audience :: Customer Service	29	0	0	0
30	Intended Audience :: Developers	30	0	0	0
31	Intended Audience :: Education	31	0	0	0
32	Intended Audience :: End Users/Desktop	32	0	0	0
33	Intended Audience :: Financial and Insurance Industry	33	0	0	0
34	Intended Audience :: Healthcare Industry	34	0	0	0
35	Intended Audience :: Information Technology	35	0	0	0
36	Intended Audience :: Legal Industry	36	0	0	0
37	Intended Audience :: Manufacturing	37	0	0	0
38	Intended Audience :: Other Audience	38	0	0	0
39	Intended Audience :: Religion	39	0	0	0
545	Framework :: Buildout :: Recipe	512	545	0	0
546	Framework :: Buildout :: Extension	512	546	0	0
42	Intended Audience :: Telecommunications Industry	42	0	0	0
43	License :: Aladdin Free Public License (AFPL)	43	0	0	0
44	License :: DFSG approved	44	0	0	0
45	License :: Eiffel Forum License (EFL)	45	0	0	0
396	Topic :: Scientific/Engineering :: Mathematics	385	396	0	0
521	Framework :: Pylons	521	0	0	0
522	Environment :: Web Environment :: ToscaWidgets	21	522	0	0
523	Framework :: Django	523	0	0	0
524	Framework :: Setuptools Plugin	524	0	0	0
525	Framework :: Twisted	525	0	0	0
526	License :: OSI Approved :: GNU Affero General Public License v3	54	526	0	0
527	Programming Language :: Python :: 2	214	527	0	0
528	Programming Language :: Python :: 2.3	214	528	0	0
529	Programming Language :: Python :: 2.4	214	529	0	0
530	Programming Language :: Python :: 2.5	214	530	0	0
531	Programming Language :: Python :: 2.6	214	531	0	0
532	Programming Language :: Python :: 2.7	214	532	0	0
533	Programming Language :: Python :: 3	214	533	0	0
534	Programming Language :: Python :: 3.0	214	534	0	0
535	Programming Language :: Python :: 3.1	214	535	0	0
536	Programming Language :: Cython	536	0	0	0
537	Framework :: CubicWeb	537	0	0	0
538	Programming Language :: Python :: 3.2	214	538	0	0
539	Topic :: Software Development :: Libraries :: pygame	405	417	539	0
540	Framework :: BFG	540	0	0	0
541	License :: Repoze Public License	541	0	0	0
542	License :: OSI Approved :: European Union Public Licence 1.0 (EUPL 1.0)	54	542	0	0
543	License :: OSI Approved :: European Union Public Licence 1.1 (EUPL 1.1)	54	543	0	0
544	License :: OSI Approved :: ISC License (ISCL)	54	544	0	0
547	Topic :: Scientific/Engineering :: Artificial Life	385	547	0	0
548	License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication	548	0	0	0
549	Framework :: CherryPy	549	0	0	0
550	Topic :: Internet :: WWW/HTTP :: Session	319	326	550	0
551	Framework :: Tryton	551	0	0	0
552	Programming Language :: Python :: Implementation	214	552	0	0
553	Programming Language :: Python :: Implementation :: CPython	214	552	553	0
554	Programming Language :: Python :: Implementation :: PyPy	214	552	554	0
555	Programming Language :: Python :: Implementation :: Jython	214	552	555	0
556	Programming Language :: Python :: Implementation :: IronPython	214	552	556	0
557	Programming Language :: Python :: Implementation :: Stackless	214	552	557	0
558	Framework :: Plone :: 3.2	518	558	0	0
559	Framework :: Plone :: 3.3	518	559	0	0
560	Framework :: Plone :: 4.0	518	560	0	0
561	Framework :: Plone :: 4.1	518	561	0	0
562	Framework :: Plone :: 4.2	518	562	0	0
563	Framework :: Plone :: 4.3	518	563	0	0
564	Programming Language :: Python :: 2 :: Only	214	527	564	0
565	Natural Language :: Galician	565	0	0	0
566	Programming Language :: Python :: 3.3	214	566	0	0
567	License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)	54	567	0	0
568	Operating System :: Microsoft :: Windows :: Windows XP	148	150	568	0
569	Operating System :: Microsoft :: Windows :: Windows Vista	148	150	569	0
570	Operating System :: Microsoft :: Windows :: Windows 7	148	150	570	0
571	Operating System :: Microsoft :: Windows :: Windows Server 2003	148	150	571	0
572	Operating System :: Microsoft :: Windows :: Windows Server 2008	148	150	572	0
573	License :: OSI Approved :: GNU Lesser General Public License v2 (LGPLv2)	54	573	0	0
574	License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)	54	574	0	0
575	License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)	54	575	0	0
576	License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)	54	576	0	0
577	License :: OSI Approved :: GNU General Public License v2 (GPLv2)	54	577	0	0
578	License :: OSI Approved :: GNU General Public License v3 (GPLv3)	54	578	0	0
579	License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)	54	579	0	0
580	License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)	54	580	0	0
581	License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)	54	581	0	0
582	Framework :: Pyramid	582	0	0	0
583	Environment :: OpenStack	583	0	0	0
584	Framework :: Bottle	584	0	0	0
585	Framework :: Flask	585	0	0	0
586	Framework :: IPython	586	0	0	0
587	Programming Language :: Python :: 3.4	214	587	0	0
\.


--
-- PostgreSQL database dump complete
--

--
-- PostgreSQL database dump
--

SET statement_timeout = 0;
SET lock_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET check_function_bodies = false;
SET client_min_messages = warning;

SET search_path = public, pg_catalog;

--
-- Data for Name: alembic_version; Type: TABLE DATA; Schema: public; Owner: -
--

COPY alembic_version (version_num) FROM stdin;
47e27f268fc2
\.

