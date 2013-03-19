ALTER TABLE "packages" ADD COLUMN "hosting_mode" text NOT NULL DEFAULT 'pypi-scrape-crawl';
ALTER TABLE "packages" ALTER COLUMN "hosting_mode" SET DEFAULT 'pypi-explicit';
