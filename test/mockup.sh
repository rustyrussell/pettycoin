#! /bin/sh

if [ $# -eq 0 ]; then
    # With no args, read stdin to scrape compiler output.
    set -- $(while read LINE; do
	case "$LINE" in
	    *undefined\ reference\ to*)
		LINE=${LINE#*undefined reference to \`}
		echo ${LINE%\'*}
		;;
	    *)
		continue
		;;
	esac; done | sort -u)
fi

for SYMBOL; do
    WHERE=$(grep -nH "^[a-z0-9_ ]* [*]*$SYMBOL(" ../*.h)
    FILE=${WHERE%%:*}
    FILE_AND_LINE=${WHERE%:*}
    LINE=${FILE_AND_LINE#*:}
    END=$(tail -n +$LINE < $FILE | grep -n ');');
    NUM=${END%%:*}

    echo "/* Generated stub for $SYMBOL */"
    tail -n +$LINE < $FILE | head -n $NUM | sed 's/);/) { fprintf(stderr, "'$SYMBOL' called!\\n"); abort(); }/'
done
