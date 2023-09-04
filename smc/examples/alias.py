from smc import session
from smc.elements.network import Alias
from smc_info import SMC_URL, API_KEY, API_VERSION

if __name__ == "__main__":
    session.login(url=SMC_URL, api_key=API_KEY, verify=False, timeout=120, api_version=API_VERSION)
    print("session OK")

try:
    # filter alias containing interface in its name
    alias_lst = list(Alias.objects.filter('interface',
                                          exact_match=False,
                                          case_sensitive=False))

    # resolve each alias for Plano
    for alias in alias_lst:
        print("alias name={} resolved value={} for Plano".format(alias.name,
                                                                 alias.resolve("Plano")))
        print("full resolved value={} for Plano".format(alias.name,
                                                        alias.full_resolve("Plano")))

except BaseException as e:
    print("ex={}".format(e))
    exit(-1)
finally:
    session.logout()
