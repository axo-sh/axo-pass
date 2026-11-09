use super::*;

fn own_file(hash: &'static str, state: OwnFileState) -> OwnFile<&'static str> {
    OwnFile { hash, state }
}

#[test]
fn publishes_if_context_is_ahead_of_published_context() {
    let mut a = session(1);
    let mut state = State::default();
    a.mint(&mut state, NOW);
    let published = state.context.clone();
    let files = [own_file("h1", OwnFileState::Joined)];

    assert!(
        !state
            .context
            .should_publish(&published, Some(&"h1"), &files)
    );

    a.mint(&mut state, NOW);

    assert!(
        state
            .context
            .should_publish(&published, Some(&"h1"), &files)
    );
}

#[test]
fn republish_after_join_ends_once_contexts_are_equal() {
    let mut a = session(1);
    let mut left = State::default();
    let m = a.mint(&mut left, NOW);
    left.store.name.write(&m, "Work");
    let left_published = left.context.clone();
    let left_files = [own_file("a1", OwnFileState::Joined)];
    let mut right = State::default();
    let right_published = right.context.clone();
    let right_files = [own_file("b1", OwnFileState::Joined)];

    // Right joins a write it had not published, and publishes.
    right.join(left.clone());
    assert!(
        right
            .context
            .should_publish(&right_published, Some(&"b1"), &right_files)
    );

    // Left joins the republished state and finds its context covers it.
    left.join(right);
    assert!(
        !left
            .context
            .should_publish(&left_published, Some(&"a1"), &left_files)
    );
}

#[test]
fn publishes_if_last_published_file_is_missing() {
    let mut a = session(1);
    let mut state = State::default();
    a.mint(&mut state, NOW);
    let published = state.context.clone();
    let ctx = &state.context;

    let other = [own_file("h0", OwnFileState::Joined)];
    assert!(ctx.should_publish(&published, Some(&"h1"), &other));
    assert!(ctx.should_publish::<&str>(&published, Some(&"h1"), &[]));

    let present = [
        OwnFileState::Joined,
        OwnFileState::Remote,
        OwnFileState::NotJoined,
    ];
    for state in present {
        let files = [own_file("h1", state)];
        assert!(!ctx.should_publish(&published, Some(&"h1"), &files));
    }
}

#[test]
fn without_recorded_publish_only_context_decides() {
    let mut a = session(1);
    let mut state = State::default();
    let empty = CausalContext::default();

    assert!(!state.context.should_publish::<&str>(&empty, None, &[]));

    a.mint(&mut state, NOW);

    assert!(state.context.should_publish::<&str>(&empty, None, &[]));
}

#[test]
fn publish_deletes_only_joined_older_own_files() {
    let joined = own_file("h1", OwnFileState::Joined);
    let remote = own_file("h2", OwnFileState::Remote);
    let not_joined = own_file("h3", OwnFileState::NotJoined);
    let published = own_file("h4", OwnFileState::Joined);

    assert!(joined.should_delete(&"h4"));
    assert!(!remote.should_delete(&"h4"));
    assert!(!not_joined.should_delete(&"h4"));
    assert!(!published.should_delete(&"h4"));
}
