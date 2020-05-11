#!/usr/bin/env bash
# Build extra targets for make.  This includes targets that are a little tricky
# to build.  This includes all versions of the draft other than the latest: all
# tagged versions and the next version for submission.  As a result, it also
# includes diffs.

# Usage: $0 <tagfile> <outputfile> [drafts ...]

drafts=("$@")
candidates=$((${#drafts[@]} * 5))

next() {
    printf "${1%-*}-%2.2d" $((1${1##*-} - 99))
}

print_sed() {
    noop_cmd="$1"
    sed_cmd="$2"
    shift 2
    if [ $# -gt 0 ]; then
        printf "$sed_cmd"
    else
        printf "$noop_cmd"
    fi
    for s in "$@"; do
        printf " -e '$s'"
    done
}

# This builds a make target for a specific tag.
build_target() {
    tag="$1"
    target_name="$2"
    source_file=
    subst=()
    for file in $(git ls-tree --name-only "$tag" | grep '^draft-'); do
        if [ "${file%.*}" = "${target_name%-*}" ]; then
            source_file="$file"
            file_tag="$target_name"
        else
            # This is the last tag for the identified file at the tag we're
            # interested in.
            prev_file_tag=$(git describe --candidates="$candidates" --tags \
                                --match "${file%.*}-*" --abbrev=0 "$tag" 2>/dev/null)

            # No previous: -00, building for HEAD: next, otherwise use tag.
            if [ -z "$prev_file_tag" ]; then
                file_tag="${file%.*}-00"
            elif [ "$tag" = HEAD ]; then
                file_tag=$(next "$prev_file_tag")
            else
                file_tag="$prev_file_tag"
            fi
        fi
        subst+=("s/${file%.*}-latest/${file_tag}/g")
    done

    if [ -z "$source_file" ]; then
        echo "warning: No file found at revision $tag for $target_name" 1>&2
        return
    fi

    target="${target_name}.${source_file##*.}"
    if [ "$tag" == HEAD ]; then
        printf "${target}: ${source_file}\n"
        printf "\t"
        print_sed cat sed "${subst[@]}"
        printf " \$< >\$@\n"
    else
        printf ".INTERMEDIATE: ${target}\n"
        printf "${target}:\n"
        printf "\tgit show \"$tag:$source_file\""
	print_sed '' ' | sed' "${subst[@]}"
        printf " >\$@\n"
    fi
}

for draft in "${drafts[@]%.*}"; do
    tags=($(git tag --list "${draft}-[0-9][0-9]"))
    for i in "${tags[@]}"; do
        build_target "$i" "$i"
    done

    if [ "${#tags[@]}" -gt 0 ]; then
        next_draft=$(next "${tags[$((${#tags[@]}-1))]}")
    else
        next_draft="${draft}-00"
    fi
    build_target HEAD "$next_draft"

    if [ "${#tags[@]}" -gt 0 ]; then
        # Write out a diff target
        printf "diff-${draft}.html: ${tags[$((${#tags[@]}-1))]}.txt ${next_draft}.txt\n"
        printf "\t-\$(rfcdiff) --html --stdout \$^ > \$@\n"
    fi
done
