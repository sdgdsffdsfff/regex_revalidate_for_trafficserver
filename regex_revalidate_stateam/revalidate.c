#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ts/ts.h>

#ifdef HAVE_PCRE_PCRE_H
#  include <pcre/pcre.h>
#else
#  include <pcre.h>
#endif

#define PLUGIN_NAME       "longcache"
#define CONFIG_TMOUT      60000
#define FREE_TMOUT        300000
#define ENABLE_TMOUT      259200
#define OVECTOR_SIZE      30

#define STA_LAST_MODIFIED      "Sta-Last-Modified"
#define STA_LAST_MODIFIED_LEN  17
static inline void*
ts_malloc(size_t s)
{
    return TSmalloc(s);
}

static inline void
ts_free(void *s)
{
    return TSfree(s);
}

typedef struct invalidate_t
{
    const char *regex_text;
    pcre *regex;
    pcre_extra *regex_extra;
    time_t epoch;
    time_t expiry;
    struct invalidate_t *next;
} invalidate_t;

typedef struct
{
    invalidate_t * volatile invalidate_list;
    char *config_file;
    volatile time_t last_load;
} plugin_state_t;

static invalidate_t *
init_invalidate_t(invalidate_t *i)
{
    i->regex_text = NULL;
    i->regex = NULL;
    i->regex_extra = NULL;
    i->epoch = 0;
    i->expiry = 0;
    i->next = NULL;
    return i;
}

static void
free_invalidate_t(invalidate_t *i)
{
    if (i->regex_extra)
#ifndef PCRE_STUDY_JIT_COMPILE
        pcre_free(i->regex_extra);
#else
        pcre_free_study(i->regex_extra);
#endif
    if (i->regex)
        pcre_free(i->regex);
    if (i->regex_text)
        pcre_free_substring(i->regex_text);
    TSfree(i);
}

static void
free_invalidate_t_list(invalidate_t *i)
{
    if (i->next)
        free_invalidate_t_list(i->next);
    free_invalidate_t(i);
}

static plugin_state_t *
init_plugin_state_t(plugin_state_t *pstate)
{
    pstate->invalidate_list = NULL;
    pstate->config_file = NULL;
    pstate->last_load = 0;
    return pstate;
}

static void
free_plugin_state_t(plugin_state_t *pstate)
{
    if (pstate->invalidate_list)
        free_invalidate_t_list(pstate->invalidate_list);
    if (pstate->config_file)
        TSfree(pstate->config_file);
    TSfree(pstate);
}

static invalidate_t *
copy_invalidate_t(invalidate_t *i)
{
    invalidate_t *iptr;
    const char *errptr;
    int erroffset;

    iptr = (invalidate_t *) TSmalloc(sizeof(invalidate_t));
    iptr->regex_text = TSstrdup(i->regex_text);
    iptr->regex = pcre_compile(iptr->regex_text, 0, &errptr, &erroffset, NULL);
    iptr->regex_extra = pcre_study(iptr->regex, 0, &errptr); 
    iptr->epoch = i->epoch;
    iptr->expiry = i->expiry;
    iptr->next = NULL;
    return iptr;
}

static invalidate_t *
copy_config(invalidate_t *old_list)
{
    invalidate_t *new_list = NULL;
    invalidate_t *iptr_old, *iptr_new;

    if (old_list)
    {
        new_list = copy_invalidate_t(old_list);
        iptr_old = old_list->next;
        iptr_new = new_list;
        while (iptr_old)
        {
            iptr_new->next = copy_invalidate_t(iptr_old);
            iptr_new = iptr_new->next;
            iptr_old = iptr_old->next;
        }
    }

    return new_list;
}

static bool
prune_config(invalidate_t **i)
{
    invalidate_t *iptr, *ilast;
    time_t now;
    bool pruned = false;

    now = time(NULL);
    if (*i)
    {
        iptr = *i;
        ilast = NULL;
        while (iptr)
        {
            if (difftime(iptr->expiry, now) < 0)
            {
                TSDebug(PLUGIN_NAME, "Removing %s expiry: %d now: %d", iptr->regex_text, (int) iptr->expiry, (int) now);
                if (ilast)
                {
                    ilast->next = iptr->next;
                    free_invalidate_t(iptr);
                    iptr = ilast->next;
                }
                else
                {
                    *i = iptr->next;
                    free_invalidate_t(iptr);
                    iptr = *i;
                }
                pruned = true;
            }
            else
            {
                ilast = iptr;
                iptr = iptr->next;
            }
        }
    }
    return pruned;
}

void 
clear_file(plugin_state_t *pstate)
{
	FILE *fp;
	struct stat s;
	fp = fopen(pstate->config_file, "w");
	if (fp)
    {
		fclose(fp);
	}
	if (stat(pstate->config_file, &s) < 0)
    {
        TSDebug(PLUGIN_NAME, "clear_file:Could not stat %s", pstate->config_file);
        return ;
    }
	pstate->last_load = s.st_mtime;
}

static bool
load_config(plugin_state_t *pstate, invalidate_t **ilist)
{
    FILE *fs;
    struct stat s;
    size_t path_len;
    char *path;
    char line[LINE_MAX];
    time_t now;
    pcre *config_re;
    const char *errptr;
    int erroffset, ovector[OVECTOR_SIZE], rc;
    int ln = 0;
    invalidate_t *iptr, *i;

    if (pstate->config_file[0] != '/')
    {
        path_len = strlen(TSConfigDirGet()) + strlen(pstate->config_file) + 2;
        path = alloca(path_len);
        snprintf(path, path_len, "%s/%s", TSConfigDirGet(), pstate->config_file);
    }
    else
	{
        path = pstate->config_file;
	}
	
    if (stat(path, &s) < 0)
    {
        TSDebug(PLUGIN_NAME, "Could not stat %s", path);
        return false;
    }
    if (s.st_mtime > pstate->last_load)
    {
        now = time(NULL);
        if (!(fs = fopen(path, "r")))
        {
            TSDebug(PLUGIN_NAME, "Could not open %s for reading", path);
            return false;
        }
        config_re = pcre_compile("^([^#].+?)\\s*$", 0, &errptr, &erroffset, NULL);
        while (fgets(line, LINE_MAX, fs) != NULL)
        {
            ln++;
            TSDebug(PLUGIN_NAME, "Processing: %d %s", ln, line);
            rc = pcre_exec(config_re, NULL, line, strlen(line), 0, 0, ovector, OVECTOR_SIZE);
            if (rc == 2)
            {
                i = (invalidate_t *) TSmalloc(sizeof(invalidate_t));
                init_invalidate_t(i);
                pcre_get_substring(line, ovector, rc, 1, &i->regex_text);
                i->epoch = now;
                i->expiry = now + ENABLE_TMOUT;
                i->regex = pcre_compile(i->regex_text, 0, &errptr, &erroffset, NULL);
                if (i->regex == NULL)
                {
                    TSDebug(PLUGIN_NAME, "%s did not compile", i->regex_text);
                    free_invalidate_t(i);
                }
                else
                {
                    i->regex_extra = pcre_study(i->regex, 0, &errptr);
                    if (!*ilist)
                    {
                        *ilist = i;
                        TSDebug(PLUGIN_NAME, "Created new list and Loaded %s %d %d", i->regex_text, (int) i->epoch, (int) i->expiry);
                    }
                    else
                    {
                        iptr = *ilist;
                        while(1)
                        {
                            if (strcmp(i->regex_text, iptr->regex_text) == 0)
                            {
								TSDebug(PLUGIN_NAME, "Updating duplicate %s", i->regex_text);
								iptr->epoch = i->epoch;
								iptr->expiry = i->expiry;
                                free_invalidate_t(i);
                                i = NULL;
                                break;
                            }
                            else if (!iptr->next)
                                break;
                            else
                                iptr = iptr->next;
                        }
                        if (i)
                        {
                            iptr->next = i;
                            TSDebug(PLUGIN_NAME, "Loaded %s %d %d", i->regex_text, (int) i->epoch, (int) i->expiry);
                        }
                    }
                }
            }
            else
                TSDebug(PLUGIN_NAME, "Skipping line %d", ln);
        }
        pcre_free(config_re);
        fclose(fs);
        clear_file(pstate);
        return true;
    }
    else
        TSDebug(PLUGIN_NAME, "File mod time is not newer: %d >= %d", (int) pstate->last_load, (int) s.st_mtime);
    return false;
}

static void
list_config(plugin_state_t *pstate, invalidate_t *i)
{
    invalidate_t *iptr;

    TSDebug(PLUGIN_NAME, "Current config:");
    if (i)
    {
        iptr = i;
        while (iptr)
        {
            TSDebug(PLUGIN_NAME, "%s epoch: %d expiry: %d", iptr->regex_text, (int) iptr->epoch, (int) iptr->expiry);
            iptr = iptr->next;
        }
    }
    else
    {
        TSDebug(PLUGIN_NAME, "EMPTY");
    }
}

static int
free_handler(TSCont cont, TSEvent event, void *edata)
{
    invalidate_t *iptr;

    TSDebug(PLUGIN_NAME, "Freeing old config");
    iptr = (invalidate_t *) TSContDataGet(cont);
    free_invalidate_t_list(iptr);
    TSContDestroy(cont);
    return 0;
}

static int
config_handler(TSCont cont, TSEvent event, void *edata)
{
    plugin_state_t *pstate;
    invalidate_t *i, *iptr;
    TSCont free_cont;
    bool updated;

    TSDebug(PLUGIN_NAME, "In config Handler");
    pstate = (plugin_state_t *) TSContDataGet(cont);
    i = copy_config(pstate->invalidate_list);

    updated = prune_config(&i);
    updated = load_config(pstate, &i) || updated;

    if (updated)
    {
        list_config(pstate, i);
        iptr = __sync_val_compare_and_swap(&(pstate->invalidate_list), pstate->invalidate_list, i);

        if (iptr)
        {
            free_cont = TSContCreate(free_handler, NULL);
            TSContDataSet(free_cont, (void *) iptr);
            TSContSchedule(free_cont, FREE_TMOUT, TS_THREAD_POOL_TASK);
        }
    }
    else
    {
        TSDebug(PLUGIN_NAME, "No Changes");
        if (i)
            free_invalidate_t_list(i);
    }
    return 0;
}

static time_t
get_date_from_cached_hdr(TSHttpTxn txn)
{
    TSMBuffer buf;
    TSMLoc hdr_loc, date_loc;
    int64_t date = 0;

    if (TSHttpTxnCachedRespGet(txn, &buf, &hdr_loc) == TS_SUCCESS)
    {
        date_loc = TSMimeHdrFieldFind(buf, hdr_loc, STA_LAST_MODIFIED, STA_LAST_MODIFIED_LEN);
        if (date_loc != TS_NULL_MLOC)
        {
             date = TSMimeHdrFieldValueInt64Get(buf, hdr_loc, date_loc,0);
             TSHandleMLocRelease(buf, hdr_loc, date_loc);
        }
        TSHandleMLocRelease(buf, TS_NULL_MLOC, hdr_loc);
    }

    return date;
}

//响应添加报文头
TSReturnCode set_resp_mimed_field(TSHttpTxn txnp,char *name,int name_length,char *value,int value_len)
{
	TSMBuffer bufp;
    TSMLoc hdr_loc;
    TSMLoc field_loc;
	if (TSHttpTxnServerRespGet(txnp, &bufp, &hdr_loc) != TS_SUCCESS) {
		return TS_ERROR;
	}
	field_loc = TSMimeHdrFieldFind(bufp, hdr_loc, name, name_length);
	if(field_loc != TS_NULL_MLOC){
	    TSMimeHdrFieldValuesClear(bufp, hdr_loc, field_loc);
	    TSMimeHdrFieldValueStringInsert(bufp, hdr_loc, field_loc, -1, value, value_len);
	    TSHandleMLocRelease(bufp, hdr_loc, field_loc);
	}else{
		if (TSMimeHdrFieldCreate(bufp, hdr_loc, &field_loc) != TS_SUCCESS) {
			return TS_ERROR;
		}
		TSMimeHdrFieldAppend(bufp, hdr_loc, field_loc);
		TSMimeHdrFieldValuesClear(bufp, hdr_loc, field_loc);
		TSMimeHdrFieldNameSet(bufp, hdr_loc, field_loc, name, name_length);
		TSMimeHdrFieldValueStringInsert(bufp, hdr_loc, field_loc, -1, value, value_len);
		TSHandleMLocRelease(bufp, hdr_loc, field_loc);
	}
	TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);
	return TS_SUCCESS;
}


static int
main_handler(TSCont cont, TSEvent event, void *edata)
{
    TSHttpTxn txn = (TSHttpTxn) edata;
    int status;
    invalidate_t *iptr;
    plugin_state_t *pstate;

    time_t date = 0, now = 0;
    char *url = NULL;
    int url_len = 0;

    switch (event)
    {
        case TS_EVENT_HTTP_CACHE_LOOKUP_COMPLETE:
            if (TSHttpTxnCacheLookupStatusGet(txn, &status) == TS_SUCCESS)
            {
                if (status == TS_CACHE_LOOKUP_HIT_FRESH)
                {
                    pstate = (plugin_state_t *) TSContDataGet(cont);
                    iptr = pstate->invalidate_list;
                    while (iptr)
                    {
                        if (!date)
                        {
                            date = get_date_from_cached_hdr(txn);
                            now = time(NULL);
                        }
						//TSDebug(PLUGIN_NAME, "date：%d,epoch:%d", (int)date, (int)iptr->epoch);
                        if ((difftime(iptr->epoch, date) >= 0) && (difftime(iptr->expiry, now) >= 0))
                        {
                            if (!url)
                                url = TSHttpTxnEffectiveUrlStringGet(txn, &url_len);
                            if (pcre_exec(iptr->regex, iptr->regex_extra, url, url_len, 0, 0, NULL, 0) >= 0)
                            {
                                TSHttpTxnCacheLookupStatusSet(txn, TS_CACHE_LOOKUP_HIT_STALE);
                                iptr = NULL;
                                TSDebug(PLUGIN_NAME, "Forced revalidate - %.*s", url_len, url);
                            }
                        }
                        if (iptr)
                            iptr = iptr->next;
                    }
                    if (url){
                        TSfree(url);
						url = NULL;
					}
                }
            }
            break;
		case TS_EVENT_HTTP_READ_RESPONSE_HDR:{
				char timestamp[100];
				memset(timestamp,'\0',sizeof(timestamp));
				now = time(NULL);
				sprintf(timestamp,"%d", (int)now);
				set_resp_mimed_field(txn,(char *)STA_LAST_MODIFIED, STA_LAST_MODIFIED_LEN,timestamp,strlen(timestamp));
			}
			break;
        default:
            break;
    }

    TSHttpTxnReenable(txn, TS_EVENT_HTTP_CONTINUE);
    return 0;
}


void
TSPluginInit (int argc, const char *argv[])
{
    TSCont main_cont, management_contp;
    plugin_state_t *pstate;
    invalidate_t *iptr = NULL;

    TSDebug(PLUGIN_NAME, "Starting plugin init.");

    pstate = (plugin_state_t *) TSmalloc(sizeof(plugin_state_t));
    init_plugin_state_t(pstate);

    pstate->config_file = TSstrdup("/sysconfig/revalidate.conf");
	
    if (!pstate->config_file)
    {
        TSDebug(PLUGIN_NAME,"Plugin requires a --config option along with a config file name.");
        free_plugin_state_t(pstate);
        return;
    }

    if (!load_config(pstate, &iptr))
	{
        TSDebug(PLUGIN_NAME, "Problem loading config from file %s", pstate->config_file);
	}
    else
    {
        pstate->invalidate_list = iptr;
        list_config(pstate, iptr);
    }

    pcre_malloc = &ts_malloc;
    pcre_free = &ts_free;

	management_contp = TSContCreate(config_handler, NULL);
	TSContDataSet(management_contp,(void*)pstate);
	TSMgmtUpdateRegister(management_contp, "TAG");
	
    main_cont = TSContCreate(main_handler, NULL);
    TSContDataSet(main_cont, (void *) pstate);
    TSHttpHookAdd(TS_HTTP_CACHE_LOOKUP_COMPLETE_HOOK, main_cont);
	TSHttpHookAdd(TS_HTTP_READ_RESPONSE_HDR_HOOK, main_cont);
	
    TSDebug(PLUGIN_NAME, "Plugin Init Complete.");
}
