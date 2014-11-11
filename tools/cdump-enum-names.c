#include <ccan/cdump/cdump.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/err/err.h>

static bool create_file(const char *name, struct cdump_type *t,
			const char *prefix)
{
	size_t i;

	printf("/* Generated from enum %s by tools/cdump-enum-names */\n"
	       "#include \"%s_names.h\"\n"
	       "\n"
	       "struct %s_names %s_names[] = {\n",
	       name, prefix, prefix, prefix);

	for (i = 0; i < tal_count(t->u.enum_vals); i++)
		printf("	{ %s, \"%s\" },\n",
		       t->u.enum_vals[i].name, t->u.enum_vals[i].name);
	printf("	{ 0, NULL }\n"
	       "};\n");
	return true;
}

int main(int argc, char *argv[])
{
	struct cdump_definitions *defs;
	const char *code;
	char *problems;

	err_set_progname(argv[0]);
	if (argc != 4)
		errx(1, "Usage: %s <headerfile> <enum> <prefix>", argv[0]);
	code = grab_file(NULL, argv[1]);
	if (!code)
		err(1, "Reading %s", argv[1]);
	defs = cdump_extract(code, code, &problems);
	if (!defs)
		errx(1, "Parsing %s: %s", argv[1], problems);

	create_file(argv[2], strmap_get(&defs->enums, argv[2]), argv[3]);
	return 0;
}
