rm -rf .git tests
find * -type f -not -name "*.zip" -not -name "x.sh" | x0 rm -f
git init
for z in ssh_complete*.zip; do
    find * -type f -not -name "*.zip" -not -name "x.sh" | x0 rm -f
    zipdump -e -p1 "$z"
    find * -type f -not -name "*.zip" | x0 git add
    git commit -m "$z" 
done
