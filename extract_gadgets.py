import os
import re
import json

SOURCE_ROOT = r"D:\tools\java-chains\java-chains.jar_src"
OUTPUT_FILE = r"D:\workspace\javaspace\JByteScanner\src\main\resources\gadgets.json"

# Regex to match @GadgetAnnotation
# matches: @GadgetAnnotation( ... )
# We need to capture the content inside carefully, dealing with newlines
ANNOTATION_PATTERN = re.compile(r"@GadgetAnnotation\s*\((.*?)\)", re.DOTALL)


def parse_dependencies(dep_str_list):
    """
    Parses a list of dependency strings into structured objects.
    Examples:
      "commons-collections:commons-collections:3.2.1" -> {g:.., a:.., v:..}
      "tomcat" -> {a: tomcat, v: *}
      "jdk < 8u121" -> {a: jdk, v: "< 8u121"}
    """
    deps = []
    for dep in dep_str_list:
        dep = dep.replace('"', "").strip()
        parts = dep.split(":")

        entry = {}
        if len(parts) == 3:
            entry = {"group": parts[0], "artifact": parts[1], "version": parts[2]}
        elif len(parts) == 2:
            # Could be group:artifact or artifact:version
            # Heuristic: if part[1] starts with digit, it's version
            if parts[1] and parts[1][0].isdigit():
                entry = {"artifact": parts[0], "version": parts[1]}
            else:
                entry = {"group": parts[0], "artifact": parts[1], "version": "*"}
        else:
            # complex string or just artifact
            # extract artifact name if possible (first word)
            match = re.match(r"^([a-zA-Z0-9_\-]+)", dep)
            if match:
                entry = {"artifact": match.group(1), "raw": dep}
            else:
                entry = {"raw": dep}

        deps.append(entry)
    return deps


def scan_file(filepath):
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    match = ANNOTATION_PATTERN.search(content)
    if not match:
        return None

    annotation_content = match.group(1)

    # Extract fields using simple regex
    name_match = re.search(r'name\s*=\s*"([^"]+)"', annotation_content)
    desc_match = re.search(r'description\s*=\s*"([^"]+)"', annotation_content)

    # Extract dependencies array: dependencies={"a", "b"}
    deps_match = re.search(r"dependencies\s*=\s*\{([^}]+)\}", annotation_content)

    if not name_match:
        return None

    gadget = {
        "name": name_match.group(1),
        "description": desc_match.group(1) if desc_match else "",
        "class": os.path.basename(filepath).replace(".java", ""),
        "dependencies": [],
    }

    if deps_match:
        # Split by comma but respect quotes
        raw_deps = deps_match.group(1)
        # Simple split by comma might break if comma inside quotes, but standard code style usually doesn't do that for deps
        dep_list = [d.strip() for d in raw_deps.split(",")]
        gadget["dependencies"] = parse_dependencies(dep_list)

    return gadget


def main():
    gadgets = []
    print(f"Scanning {SOURCE_ROOT}...")

    for root, dirs, files in os.walk(SOURCE_ROOT):
        for file in files:
            if file.endswith(".java"):
                path = os.path.join(root, file)
                result = scan_file(path)
                if result:
                    gadgets.append(result)

    print(f"Found {len(gadgets)} gadgets.")

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(gadgets, f, indent=2, ensure_ascii=False)

    print(f"Saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
