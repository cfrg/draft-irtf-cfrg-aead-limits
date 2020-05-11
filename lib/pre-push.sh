#!/usr/bin/env bash

err=0
tags=0
while read local_ref local_sha remote_ref remote_sha; do
    if [[ "${local_ref#refs/tags/draft-}" != "${local_ref}" ]]; then
        if [[ -z "$(git for-each-ref --format '%(taggeremail)' "${local_ref}")" ]]; then
            echo "pre-push: tag ${local_ref#refs/tags/} is not an annotated tag" 1>&2
	    err=1
	fi
	tags=$((tags+1))
    fi
done
if [[ $tags -gt 1 ]]; then
    echo "pre-push: more than one tag pushed, which circle doesn't currently handle" 1>&2
    err=2
fi
[[ $err -eq 0 ]] || echo "pre-push: use git push --no-verify to override this check" 1>&2
exit $err
