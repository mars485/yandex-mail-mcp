from test_server import client, imap, call


def test_incremental_uid_star_edge_and_validity(client, imap):
    imap.search.return_value = [7, 8, 9]
    result = call(client, 'search_new_messages', {'after_uid': 8, 'uidvalidity': 99, 'limit': 1})
    assert result['next_after_uid'] == 9
    assert result['total'] == 1
    imap.search.assert_called_once_with(['UID', '9:*'])
    imap.search.reset_mock()
    assert not call(client, 'search_new_messages', {'after_uid': 8, 'uidvalidity': 100})['ok']
    imap.search.assert_not_called()
    assert call(client, 'search_new_messages', {'after_uid': 4294967295, 'uidvalidity': 99})['total'] == 0
    imap.search.assert_not_called()


def test_or_deduplicates_and_validates_before_search(client, imap):
    imap.search.side_effect = [[7, 8], [8, 9]]
    result = call(client, 'search_any', {'conditions': [{'sender': 'a@example.invalid'}, {'unread': True}]})
    assert result['total'] == 3
    imap.search.reset_mock()
    assert not call(client, 'search_any', {'conditions': [{'raw_command': 'EXPUNGE'}]})['ok']
    imap.search.assert_not_called()


def test_count_and_folder_tree_readonly(client, imap):
    imap.search.return_value = [7, 8]
    assert call(client, 'count_messages', {'filters': {'unread': True}})['count'] == 2
    imap.select_folder.assert_called_with('INBOX', readonly=True)
    imap.list_folders.return_value = [((), b'|', 'Projects|2026'), ((), None, 'INBOX')]
    folders = call(client, 'get_folder_tree')['folders']
    assert folders[0]['parent'] == 'Projects'
    assert folders[1]['parent'] is None


def test_links_never_follow_external_urls_and_omit_non_http(client, imap):
    raw = b'From: Sender <a@example.invalid>\r\nReply-To: reply@example.invalid\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<a href="https://example.invalid/a">a</a><a href="javascript:alert(1)">bad</a><a href="https://example.invalid/a">duplicate</a>'
    imap.fetch.return_value = {7: {b'FLAGS': (), b'RFC822.SIZE': len(raw), b'BODY[]': raw}}
    result = call(client, 'get_message_links', {'uid': 7, 'uidvalidity': 99})
    assert result['links'] == ['https://example.invalid/a']
    assert result['fetched_external_resources'] is False
    addresses = call(client, 'get_message_addresses', {'uid': 7})['addresses']
    assert addresses['Reply-To'][0]['address'] == 'reply@example.invalid'
    imap.set_flags.assert_not_called(); imap.add_flags.assert_not_called()
    assert all('PEEK' in item for args in imap.fetch.call_args_list for item in args.args[1] if item.startswith('BODY'))


def test_inventory_budget_blocks_body_read(client, imap):
    imap.fetch.return_value = {7: {b'RFC822.SIZE': 17 * 1024**2}}
    result = call(client, 'get_attachment_inventory', {'message_uids': [7], 'uidvalidity': 99})
    assert not result['ok']
    assert imap.fetch.call_count == 1
