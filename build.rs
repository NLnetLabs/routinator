fn main() {
    eprintln!(
        "\n\nYou are using an outdated branch of the Routinator repository.\n\n\
         The default branch is now \"main\".\n\n\
         Please run 'git checkout main' before building.\n\n\
        "
    );
    panic!();
}
