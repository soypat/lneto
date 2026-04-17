# import-examples
This folder contains examples that need external imports to work. 

This is done to avoid adding dependencies to lneto's go.mod file.
- Trivial Auditing
    - No dependency analysis needed for vulnerability scanning
- Eliminate a whole set of attack vectors for lneto importers
- Ensures nothing outside Lneto gets compiled maintaining binary sizes small
