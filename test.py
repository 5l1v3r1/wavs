def _resolve_path(self, base_path, path):
    if not "../" in path:
        return f'{base_path}{path}'

    # vulnerabilities/brute/
    # ../../vulnerabilities/fi/.

    dir_ups = path.count('../')
    new_path = path.replace('../', '')
    begin_slash = (base_path[0] == '/')
    explode_base = base_path.split('/')
    explode_base = list(filter(('').__ne__, explode_base))
    new_base = explode_base[:-dir_ups]

    if begin_slash:
        final = f'/{"/".join(new_base)}/{new_path}'
    else:
        final = f'{"/".join(new_base)}/{new_path}'

    return final
