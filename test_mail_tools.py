import base64
import asyncio
import hashlib
import io
from dataclasses import replace
from email.message import EmailMessage

import pytest
from pypdf import PdfWriter
from starlette.testclient import TestClient

import oauth_auth
import server
from test_server import CFG, BASE, AUTH, call, rpc, imap


@pytest.fixture
def client(tmp_path):
    with TestClient(server.build_app(replace(CFG, state_dir=str(tmp_path))), base_url=BASE) as c:
        yield c


def test_all_write_tools_enforce_read_token(client, imap):
    tools = rpc(client, 'tools/list')['tools']
    writes = [t for t in tools if not t['annotations']['readOnlyHint']]
    assert len(writes) == 22
    for t in writes:
        args = {}
        schema = t['inputSchema']
        for key in schema.get('required', []):
            prop = schema['properties'][key]
            args[key] = {'integer': 7, 'string': 'fixture', 'array': [], 'object': {}}[prop['type']]
        result = call(client, t['name'], args, {**AUTH, 'Authorization': 'Bearer '+CFG.read_token})
        assert result['ok'] is False, t['name']
    imap.select_folder.assert_not_called()
    imap.add_flags.assert_not_called()
    imap.move.assert_not_called()


@pytest.mark.parametrize('values', [[], [0], [-1], list(range(1,102))])
def test_invalid_batches_never_select(client, imap, values):
    assert not call(client, 'bulk_move_messages', {'message_uids': values, 'uidvalidity':99, 'destination':'Archive'})['ok']
    imap.select_folder.assert_not_called()


def test_stale_batch_and_missing_uid_block_all_mutations(client, imap):
    args = {'message_uids':[7,8], 'uidvalidity':100, 'destination':'Archive', 'dry_run':False}
    assert not call(client,'bulk_move_messages',args)['ok']
    args['uidvalidity'] = 99
    assert not call(client,'bulk_move_messages',args)['ok']
    imap.move.assert_not_called()


def test_batch_preview_does_not_mutate_and_no_move_fallback(client, imap):
    args = {'message_uids':[7], 'uidvalidity':99, 'destination':'Archive'}
    assert call(client,'bulk_move_messages',args)['dry_run']
    imap.move.assert_not_called()
    imap.has_capability.return_value = False
    assert not call(client,'bulk_move_messages',{**args,'dry_run':False})['ok']
    imap.copy.assert_not_called(); imap.delete_messages.assert_not_called(); imap.expunge.assert_not_called()


def test_move_and_copy_do_not_drop_original_flags(client, imap):
    args = {'message_uids':[7], 'uidvalidity':99, 'destination':'Archive', 'dry_run':False}
    assert call(client,'bulk_move_messages',args)['ok']
    imap.move.assert_called_once_with([7],'Archive')
    assert call(client,'bulk_copy_messages',args)['ok']
    imap.copy.assert_called_once_with([7],'Archive')
    imap.set_flags.assert_not_called(); imap.delete_messages.assert_not_called()


@pytest.mark.parametrize('name,args', [
    ('move_message',{'uid':7,'destination':'Bin|child'}),
    ('bulk_move_messages',{'message_uids':[7],'destination':'Bin|child','dry_run':False}),
    ('copy_message',{'uid':7,'destination':'Bin|child','dry_run':False}),
])
def test_trash_descendants_blocked_everywhere(client, imap, name, args):
    imap.list_folders.return_value = [((),b'|','INBOX'),((b'\\Trash',),b'|','Bin'),((),b'|','Bin|child')]
    assert not call(client,name,{'uidvalidity':99,**args})['ok']
    imap.move.assert_not_called(); imap.copy.assert_not_called()


@pytest.mark.parametrize('flag',['\\Deleted','\\Draft','\\Recent','mcp_custom','x\r\nLOGOUT'])
def test_dangerous_flags_rejected(client, imap, flag):
    assert not call(client,'set_message_flags',{'uid':7,'uidvalidity':99,'add':[flag]})['ok']
    imap.add_flags.assert_not_called(); imap.set_flags.assert_not_called()


def test_flag_changes_preserve_keywords_and_verify_result(client, imap):
    imap.get_flags.return_value = {7:(b'\\Seen',b'encrypted',b'\\Flagged')}
    assert call(client,'mark_flagged',{'uid':7,'uidvalidity':99})['ok']
    imap.add_flags.assert_called_once_with([7],['\\Flagged'])
    imap.set_flags.assert_not_called()
    imap.get_flags.return_value = {7:(b'encrypted',)}
    assert not call(client,'mark_flagged',{'uid':7,'uidvalidity':99})['ok']


def test_label_lifecycle_persisted_without_native_claims(client, imap, tmp_path):
    first = call(client,'create_label',{'name':'🛡 Безопасность'})
    second = call(client,'create_label',{'name':'🛡 Безопасность'})
    assert first['created'] and not second['created']
    assert first['label'] == second['label'] and first['native_web_labels'] is False
    ident = first['label']['id']; keyword = first['label']['keyword']
    call(client,'rename_label',{'label_id':ident,'new_name':'Безопасность'})
    assert call(client,'list_labels')['labels'][0]['keyword'] == keyword
    # Recreate the application with the same persistent catalog.
    with TestClient(server.build_app(replace(CFG,state_dir=str(tmp_path))),base_url=BASE) as c:
        assert call(c,'list_labels')['labels'][0]['name'] == 'Безопасность'
    imap.select_folder.return_value = {b'UIDVALIDITY':99,b'PERMANENTFLAGS':(b'\\*',)}
    args = {'message_uids':[7],'uidvalidity':99,'label_ids':[ident]}
    assert call(client,'apply_labels',args)['dry_run']
    imap.add_flags.assert_not_called()
    imap.get_flags.return_value = {7:(keyword.encode(),b'\\Seen',b'encrypted')}
    assert call(client,'apply_labels',{**args,'dry_run':False})['ok']
    imap.add_flags.assert_called_once_with([7],[keyword])
    imap.set_flags.assert_not_called()


def test_unknown_labels_and_stale_validity_do_not_mutate(client, imap):
    assert not call(client,'apply_labels',{'message_uids':[7],'uidvalidity':99,'label_ids':['unknown'],'dry_run':False})['ok']
    lab = call(client,'create_label',{'name':'Test'})['label']['id']
    assert not call(client,'apply_labels',{'message_uids':[7],'uidvalidity':100,'label_ids':[lab],'dry_run':False})['ok']
    imap.add_flags.assert_not_called()


def mime_fixture(imap, attachment=b'hello attachment', mime='text/plain'):
    m=EmailMessage(); m['Subject']='Test'; m['Message-ID']='<test@example.invalid>'; m.set_content('Body')
    main,sub=mime.split('/')
    m.add_attachment(attachment,maintype=main,subtype=sub,filename='../../example.txt')
    raw=m.as_bytes()
    def fetch(values, fields):
        if any('BODY.PEEK' in x for x in fields):
            return {7:{b'BODY[]<0>':raw}}
        return {7:{b'FLAGS':(b'encrypted',),b'RFC822.SIZE':len(raw)}}
    imap.fetch.side_effect=fetch
    return raw


def test_attachment_chunks_and_hash_are_exact_without_files(client, imap):
    data=b'0123456789'; mime_fixture(imap,data)
    result=call(client,'list_attachments',{'uid':7,'uidvalidity':99})
    assert result['attachments'][0]['size_bytes']==10
    result=call(client,'download_attachment',{'uid':7,'attachment_index':0,'offset':3,'length':4})
    assert base64.b64decode(result['data_base64'])==b'3456'
    assert result['sha256']==hashlib.sha256(data).hexdigest() and result['next_offset']==7
    assert result['filename']=='../../example.txt'  # returned as metadata, never used as a path
    imap.add_flags.assert_not_called()
    assert all('BODY.PEEK' in str(x) or 'RFC822.SIZE' in str(x) for x in imap.fetch.call_args_list)


def test_attachment_bounds_and_oversize_do_not_fetch_body(client, imap):
    assert not call(client,'download_attachment',{'uid':7,'attachment_index':0,'length':262145})['ok']
    imap.fetch.assert_not_called()
    imap.fetch.return_value={7:{b'RFC822.SIZE':server.MAX_MESSAGE_BYTES+1}}
    assert not call(client,'list_attachments',{'uid':7})['ok']
    assert 'BODY.PEEK' not in str(imap.fetch.call_args)


def test_attachment_text_and_encrypted_pdf(client, imap):
    mime_fixture(imap,b'hello attachment')
    assert call(client,'extract_attachment_text',{'uid':7,'attachment_index':0})['text']=='hello attachment'
    writer=PdfWriter(); writer.add_blank_page(width=100,height=100); writer.encrypt('fixture')
    stream=io.BytesIO(); writer.write(stream)
    mime_fixture(imap,stream.getvalue(),'application/pdf')
    result=call(client,'extract_attachment_text',{'uid':7,'attachment_index':0})
    assert not result['ok'] and 'PDF' in result['error']
    imap.add_flags.assert_not_called()


def test_structured_search_and_filter_validation(client, imap):
    imap.search.return_value=[]
    assert call(client,'advanced_search',{'filters':{'sender':'Тест','unread':False,'min_bytes':100,'message_id':'<a@b>'}})['ok']
    args=imap.search.call_args.args[0]
    assert args==['ALL','FROM','Тест','SEEN','LARGER',100,'HEADER','Message-ID','<a@b>']
    imap.search.reset_mock()
    for filters in [{'raw':'DELETE 1:*'},{'subject':'x\r\nLOGOUT'},{'unread':'false'},{'min_bytes':-1},{'keyword':'x) ALL ('}]:
        assert not call(client,'advanced_search',{'filters':filters})['ok']
    imap.search.assert_not_called()


def test_yandex_header_backend_error_uses_bounded_explicit_fallback(client, imap):
    imap.search.side_effect = [server.IMAPClient.Error('backend unavailable'), [7, 9]]
    imap.fetch.return_value = {9: {b'RFC822.SIZE': 10, b'FLAGS': (), b'BODY[HEADER]<0>': b'Message-ID: <fixture@test>\r\n'}}
    result = call(client, 'find_message_by_id', {'message_id':'<fixture@test>', 'folders':['INBOX'], 'scan_limit':1})
    assert result['ok'] and result['truncated']
    assert result['search_methods'] == ['bounded_header_scan']
    assert result['messages'][0]['uid'] == 9
    assert all(args.args[0] == [9] for args in imap.fetch.call_args_list)


def test_non_header_imap_failure_is_not_hidden_by_fallback(client, imap):
    imap.search.side_effect = server.IMAPClient.Error('backend unavailable')
    result = call(client,'advanced_search',{'filters':{'subject':'fixture'}})
    assert not result['ok']
    assert imap.search.call_count == 1


def test_stats_use_status_without_loading_mail(client, imap):
    imap.folder_status.return_value={b'MESSAGES':100,b'UNSEEN':20,b'UIDNEXT':500,b'UIDVALIDITY':99}
    result=call(client,'get_folder_stats')
    assert result['messages']==100 and result['unseen']==20
    imap.fetch.assert_not_called(); imap.search.assert_not_called()


def test_rename_protects_system_and_create_is_idempotent(client, imap):
    imap.folder_exists.return_value=False
    assert not call(client,'rename_folder',{'folder':'INBOX','new_name':'Other','dry_run':False})['ok']
    imap.rename_folder.assert_not_called()
    assert call(client,'create_folder',{'name':'Archive'})['created'] is False
    imap.create_folder.assert_not_called()


def test_backchannel_does_not_change_token_issuer(monkeypatch):
    monkeypatch.setattr(oauth_auth,'BACKCHANNEL_ISSUER',oauth_auth.ISSUER.replace('auth.example.com','auth.example.com:18443'))
    oauth_auth.validate_config()
    monkeypatch.setattr(oauth_auth,'BACKCHANNEL_ISSUER','https://attacker.invalid/')
    with pytest.raises(ValueError): oauth_auth.validate_config()


def test_jwks_proxy_port_failover_keeps_tls_and_fixed_urls(monkeypatch):
    import jwt
    import httpx2
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(),as_dict=True)
    jwk.update(kid='fixture',use='sig',alg='RS256')
    alternate=oauth_auth.ISSUER.replace('auth.example.com','auth.example.com:18443')+'jwks/'
    monkeypatch.setattr(oauth_auth,'JWKS_FETCH_URL',alternate)
    requests=[]
    def handler(request):
        requests.append(str(request.url))
        assert request.headers['Host']=='auth.example.com'
        if request.url.port != 18443: raise httpx2.ConnectError('fixture connection refused')
        return httpx2.Response(200,json={'keys':[jwk]})
    client=httpx2.AsyncClient
    def factory(**kwargs):
        assert kwargs['follow_redirects'] is False and kwargs.get('verify',True) is True
        return client(transport=httpx2.MockTransport(handler),**kwargs)
    monkeypatch.setattr(oauth_auth.httpx2,'AsyncClient',factory)
    assert 'fixture' in asyncio.run(oauth_auth.AuthentikVerifier().fetch_keys())
    assert requests==[oauth_auth.JWKS_URL,alternate]
