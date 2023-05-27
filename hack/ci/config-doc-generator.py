import re


def read_config(filename):
    with open(filename, "r") as f:
        return "".join(f.readlines())


def replacetext(src_file, dest_file, search_text, replace_text):
    with open(src_file, "r+") as src:
        src_file = src.read()  # Read
        src.close()
        with open(dest_file, "r+") as dest:
            dest_file = re.sub(search_text, replace_text, src_file)  # Replace
            dest.seek(0)  # Setting the position to the top of the page to insert data
            dest.write(dest_file)  # Write

            # Truncating the file size
            dest.truncate()
            dest.close()


def main():
    search_text = "<!-- TEXT REPLACE -->"
    replace_text = read_config("example.dae")

    replacetext(
        "docs/templates/example-config.md",
        "docs/sync/example-config.md",
        search_text,
        replace_text,
    )


if __name__ == "__main__":
    main()
