-- THIS FILE IS OUT OF DATE

-- Database creation is now under the control of the Warehouse project. This
-- file does not reflect the current schema of the PyPI service.

-- NOTE: PyPI requires the citext extension

BEGIN;

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


COMMIT;
