import lief

def check_elf_security(file_path):
    print(f"Checking ELF file: {file_path}")

    # Load the ELF file
    elf = lief.parse(file_path)

    # Check for modifications in critical sections
    if has_modified_critical_sections(elf):
        print("WARNING: Modifications detected in critical sections")

    # Check for suspicious or encrypted sections
    check_suspicious_sections(elf)

    # Check for dynamic linking abuse
    check_dynamic_linking_abuse(elf)

    # Check for executable stack
    check_executable_stack(elf)

    # Check if the ELF file is built as a Position-Independent Executable (PIE)
    check_pie_format(elf)

    # Check for setuid or setgid permissions
    check_setuid_setgid_permissions(elf)

    # Close the ELF file
    elf.close()

def has_modified_critical_sections(elf):
    critical_sections = {".text", ".data", ".bss"}

    for section in elf.sections:
        section_name = section.name.lower()
        section_data = section.content

        if section_name in critical_sections and len(section_data) > 0:
            return True

    return False

def check_suspicious_sections(elf):
    print("Checking for suspicious or encrypted sections...")
    for section in elf.sections:
        section_name = section.name.lower()
        section_data = section.content

        if ".evil" in section_name or ".backdoor" in section_name:
            print(f"WARNING: Suspicious section name found: {section_name}")

        if section.has(lief.ELF.SECTION_FLAGS.ENCRYPTED) or section.has(lief.ELF.SECTION_FLAGS.COMPRESSED):
            print(f"WARNING: Encrypted or compressed section found: {section_name}")

def check_dynamic_linking_abuse(elf):
    print("Checking for dynamic linking abuse...")
    if elf.header.has(lief.ELF.DYNAMIC_TAGS.DYNAMIC):
        dynamic_tags = elf.header[lief.ELF.DYNAMIC_TAGS.DYNAMIC]
        for entry in dynamic_tags.entries:
            if entry.tag == lief.ELF.DYNAMIC_TAGS.NEEDED:
                library_name = elf.dynamic_entries[entry.val].name
                print(f"WARNING: Dynamic linking dependency: {library_name}")

def check_executable_stack(elf):
    print("Checking for executable stack...")
    if elf.header.has(lief.ELF.SEGMENT_TYPES.GNU_STACK):
        if elf.header[lief.ELF.SEGMENT_TYPES.GNU_STACK].flags & lief.ELF.SEGMENT_FLAGS.X:
            print("WARNING: Executable stack found")

def check_pie_format(elf):
    print("Checking for PIE format...")
    if not elf.is_pie:
        print("WARNING: Non-PIE format detected")

def check_setuid_setgid_permissions(elf):
    print("Checking for setuid or setgid permissions...")
    if elf.header.has(lief.ELF.DYNAMIC_TAGS.FLAGS):
        flags = elf.header[lief.ELF.DYNAMIC_TAGS.FLAGS]
        if flags.value & lief.ELF.DYNAMIC_FLAGS.SETUID or flags.value & lief.ELF.DYNAMIC_FLAGS.SETGID:
            print("WARNING: Setuid or setgid permissions detected")

# Usage example
check_elf_security("path/to/your/file.elf")
