# Adopting a Draft

When a working group adopts an individual draft that was created with this
template, the obvious ways of migrating a repository to a different organization
are often not great.

Firstly, **do not create a fork**.  There are better options.


## Best Option - Transfer the Repository

A transfer means that all the pull requests, issues and any CI configuration are moved
in addition to the code (the drafts).

To do this, make the owner of the repository part of the working group organization.
You need to give them the ability to create repositories in order for this to be
allowed.

The owner of the repository can go to the settings tab for the repository and transfer. 
This can be found at the very bottom of the page, in the "Danger Zone".

See the [GitHub instructions for transferring repositories](https://help.github.com/articles/about-repository-transfers/).


## Alternative - Copy History

In case you can't transfer, you can copy the history of the old repository into
a new repository.  For this, you don't need any special roles, just the ability
to push to the new repository.  This won't copy or move issues or pull requests.

Make a new repository.  Make sure that it is empty when you make it (don't
create a README when GitHub asks).  Then make a new repository locally:

```sh
$ git init new-repo
$ cd new-repo
$ git remote add origin https://github.com/new-owner/new-repo
```

Then pull the contents of the old repo in:

```sh
$ git pull https://github.com/old-owner/old-repo $DEFAULT_BRANCH
$ git push
```

You then need to setup the `gh-pages` and `gh-issues` 
branches:

```sh
$ make
$ make -f lib/setup.mk setup-ghpages setup-ghissues
```


## Cleanup

After transfering or copying you might want to rebuild the README:

```sh
$ make -f lib/setup.mk README.md
$ git commit -m "Update README" README.md
```

 If you have made changes to the README, you can just update the intro text and
 the links.
 
 Any copies of the repository should have any clone that references the old
 location updated.  The old location will continue to work, but it's good pratice
 to change:
 
 ```sh
 $ git remote set-url origin https://github.com/new/repo
 ```
 
 You should also update any CI configuration and links to your repo from other
 places.
