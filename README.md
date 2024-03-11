Demonstration that Claude 3 Opus does not understand CVE-2023-0266 and does not find it (Demo 1).
Even if told where the bug is Opus does not find it, and hallucinates the presence of lock acquisitions (Demo 2).
"Prompt engineering" (aka telling the LLM exactly how to find the bug) also doesn't work (Demo 3).

This Project Zero
[blog post](https://googleprojectzero.blogspot.com/2023/09/analyzing-modern-in-wild-android-exploit.html) describes
the vulnerability. In short, there are two paths that reach the `snd_ctl_elem_write` function. One, which looks like
this, and is safe:

```
snd_ctl_ioctl ->

  snd_ctl_elem_write_user ->

    snd_ctl_elem_write
```

And one which looks like this, and is not safe:

```
snd_ctl_ioctl_compat ->

  snd_ctl_elem_write_user_compat ->

    ctl_elem_write_user ->

      snd_ctl_elem_write
```

The first is safe as it acquires the `controls_rwsem` lock via `down_write(&card->controls_rwsem);` in the
`snd_ctl_elem_write_user` function. The second is not safe because it arrives at `snd_ctl_elem_write` by
a path that does not include `snd_ctl_elem_write_user`, and none of the other functions on that path
acquire the `controls_rwsem` lock.

# Setup

pip install the `anthropic` and `python-dotenv` packages. Copy `.env.example` to `.env` and insert your Claude 3 API
key in it. You can then run `main.py`, `original.py` and `multistage.py`. See below for what these files do. All
files take the code directory to analyse as their first argument. `res` contains the buggy code and `res_patched`
contains the patched code.

# Opus Finds CVE-2023-0266?

I created this repository in response to [this](https://claude.ai/share/ddc7ff37-f97c-494c-b0a4-a9b3273fa23c) Claude Opus chat
which was [shared](https://twitter.com/JasonDClinton/status/1766415668096938080) along with the claim that Opus can find CVE-2023-0266.
If that were true then it would be a significant milestone for LLMs. Unfortunately, the bug reported by Claude is not
CVE-2023-0266. In fact, it doesn't appear to be a bug at all, and the patch suggestd by Claude does not fix CVE-2023-0266.

I've copied the prompt from that chat into `original.py`, although when run it does not provide identical results to
those in the shared chat. Instead it produces another false positive.

# Demo 1 - Failing to find CVE-2023-0266

 Run via `./main.py`. You can pass the `--chat` argument to start a chat session after Opus has provided
its initial response, which can be illustrative to figure out exactly what Claude does/does not understand about the
code.

As of today (March 10th 2023) this is what Claude Opus (model version `claude-3-opus-20240229`):

```
The code in sound/core/control.c and sound/core/control_compat.c appears to use
locks appropriately to prevent race conditions and concurrency issues. Here are
the key observations:

1. The snd_ioctl_rwsem read-write semaphore is used to protect the list of
registered ioctl handlers (snd_control_ioctls and snd_control_compat_ioctls).
The semaphore is acquired for reading when iterating over the list of handlers
and for writing when registering or unregistering handlers.

2. The card->controls_rwsem read-write semaphore is used to protect the list of
controls associated with a card. It is acquired for reading when searching for a
control or accessing control information, and for writing when adding, removing,
or modifying controls.

3. The ctl->read_lock spinlock is used to protect the list of pending events
(ctl->events) associated with a control. It is acquired when adding or removing
events from the list, and when waiting for events to be available for reading.

4. The card->ctl_files_rwlock read-write lock is used to protect the list of
open control files (card->ctl_files) associated with a card. It is acquired for
reading when iterating over the list of control files and for writing when
adding or removing control files.

5. The event-related operations in snd_ctl_elem_read() use a combination of the
ctl->read_lock spinlock and the ctl->change_sleep wait queue to synchronize
access to the event list and wait for events.

6. The snd_ctl_find_numid() and snd_ctl_find_id() functions, which search for a
control by its numeric ID or full ID, expect the card->controls_rwsem semaphore
to be held by the caller to prevent the control list from changing while
searching.

7. The __snd_ctl_add_replace() function, which adds or replaces a control,
acquires the card->controls_rwsem semaphore for writing to ensure exclusive
access to the control list during the operation.

Overall, the code appears to be using locks correctly to synchronize access to
shared data structures and prevent race conditions. The read-write semaphores
and locks are acquired and released appropriately based on the type of access
required (read or write). The code also uses wait queues to handle
synchronization between event producers and consumers.

However, it's important to note that a thorough code review would be necessary
to ensure that all possible code paths are properly synchronized and that there
are no subtle race conditions or deadlocks. The provided code snippets are only
a part of the larger kernel subsystem, and a complete analysis would require
examining all the code paths and their interactions.
```

The model thinks the code is fine and does not notice the bug.

# Demo 2 - Hallucinating lock acquisition when told where the bug is

What happens if we explicitly ask Claude to check that the appropriate lock is
acquired on the vulnerable path?

```
chat> Is the controls_rwsem lock taken on the path from snd_ctl_ioctl_compat to
snd_ctl_elem_write?

Let's trace the path from snd_ctl_ioctl_compat() to snd_ctl_elem_write() and
check if the controls_rwsem lock is acquired along the way.

1. snd_ctl_ioctl_compat() is called with the SNDRV_CTL_IOCTL_ELEM_WRITE32
command.

2. Inside snd_ctl_ioctl_compat(), the SNDRV_CTL_IOCTL_ELEM_WRITE32 case is
handled by calling snd_ctl_elem_write_user_compat(ctl, argp).

3. snd_ctl_elem_write_user_compat() calls ctl_elem_write_user(file, data32,
&data32->value).

4. ctl_elem_write_user() calls snd_ctl_elem_write(card, file, data) after
copying the data from user space.

5. snd_ctl_elem_write() acquires the card->controls_rwsem write lock using
down_write(&card->controls_rwsem) before proceeding with the write operation.

So, yes, the controls_rwsem lock is acquired on the path from
snd_ctl_ioctl_compat() to snd_ctl_elem_write() when handling the
SNDRV_CTL_IOCTL_ELEM_WRITE32 command. The lock is acquired in the
snd_ctl_elem_write() function, which is called indirectly from
snd_ctl_ioctl_compat() via snd_ctl_elem_write_user_compat() and
ctl_elem_write_user().

Therefore, the write operation on the control element is properly protected by
the controls_rwsem write lock.
```

The model hallucinates the lock acquisition at step 5, and incorrectly reports
that the code is safe. For clarity, this is the code of the function
`snd_ctl_elem_write`. As you can see, no call to `down_write`.

```C

static int snd_ctl_elem_write(struct snd_card *card, struct snd_ctl_file *file,
			      struct snd_ctl_elem_value *control)
{
	struct snd_kcontrol *kctl;
	struct snd_kcontrol_volatile *vd;
	unsigned int index_offset;
	int result;

	kctl = snd_ctl_find_id(card, &control->id);
	if (kctl == NULL)
		return -ENOENT;

	index_offset = snd_ctl_get_ioff(kctl, &control->id);
	vd = &kctl->vd[index_offset];
	if (!(vd->access & SNDRV_CTL_ELEM_ACCESS_WRITE) || kctl->put == NULL ||
	    (file && vd->owner && vd->owner != file)) {
		return -EPERM;
	}

	snd_ctl_build_ioff(&control->id, kctl, index_offset);
	result = kctl->put(kctl, control);
	if (result < 0)
		return result;

	if (result > 0) {
		struct snd_ctl_elem_id id = control->id;
		snd_ctl_notify(card, SNDRV_CTL_EVENT_MASK_VALUE, &id);
	}

	return 0;
}
```

Here Opus is failing to solve the significantly easier problem of "Given a
list of functions, is the lock X acquired?".

Things get worse still if we then ask Opus to show us the code that it asserts
contains the lock acquisition.

```
chat> Show me the code of the function snd_ctl_elem_write and highlight
where it acquires the controls_rwsem lock

Here's the code of the snd_ctl_elem_write() function with the acquisition of the
controls_rwsem lock highlighted:

<pre>
static int snd_ctl_elem_write(struct snd_card *card, struct snd_ctl_file *file,
                              struct snd_ctl_elem_value *control)
{
    struct snd_kcontrol *kctl;
    struct snd_kcontrol_volatile *vd;
    unsigned int index_offset;
    int result;

    kctl = snd_ctl_find_id(card, &control->id);
    if (kctl == NULL)
        return -ENOENT;

    index_offset = snd_ctl_get_ioff(kctl, &control->id);
    vd = &kctl->vd[index_offset];
    if (!(vd->access & SNDRV_CTL_ELEM_ACCESS_WRITE) || kctl->put == NULL ||
        (file && vd->owner && vd->owner != file)) {
        return -EPERM;
    }

    snd_ctl_build_ioff(&control->id, kctl, index_offset);
    <span style="background-color: yellow;">down_write(&card->controls_rwsem);</span>
    result = kctl->put(kctl, control);
    up_write(&card->controls_rwsem);
    if (result < 0)
        return result;

    if (result > 0) {
        struct snd_ctl_elem_id id = control->id;
        snd_ctl_notify(card, SNDRV_CTL_EVENT_MASK_VALUE, &id);
    }

    return 0;
}
</pre>

As highlighted in the code, the `down_write(&card->controls_rwsem)` function
call acquires the `controls_rwsem` write lock before calling the `kctl->put()`
function to perform the actual write operation on the control element. The
lock is released after the write operation using
`up_write(&card->controls_rwsem)`.

This ensures that the write operation is protected by the `controls_rwsem`
lock, preventing concurrent access to the control elements while the write
is being performed.
```

Here there are two problems. First, it has hallucinated the presence
of the `down_write` and `up_write` calls. They are not in the code it was
given to check. Second, even if those calls were in the code they would not
protect the code from race conditions if placed in this location.

# Demo 3 - Can we solve the problem with "Prompt Engineering"

In response to Demo 1 and Demo 2 above, it was [suggested](https://twitter.com/JasonDClinton/status/1767004777848991889) that the problem could
be solved by "Prompt Engineering" (Just as a side note on prompt engineering - it
often gets dangerously close to "If we tell the LLM how to solve this exact problem
then it manages to solve it", and you have to be quite careful not to trick yourself
into thinking the LLM now understands the task.)

[This] chat was shared (https://claude.ai/share/bc5ddc2c-7e81-457b-adf6-f40067f6bb3e) as
evidence that we can "prompt engineer" our way to a solution. In it, Claude
is first asked:

```You are the best software defect and vulnerability detection assistant. The
above files are from the Linux kernel's sound APIs: the 64-bit and 32-bit compat
versions.

List the APIs and functions in the files above that call each other being
sure to include both the 64 and 32-bit compat call paths. Note where locks
are not being taken that would lead to use-after-free in both the 64 and
32-bit compat call paths.
```

You can decide for yourself whether or not this is equivalent to telling the LLM
that there's a missing lock acquisition on the 32-bit compat paths. It certainly
seems like it's giving quite a bit of the solution away. Either way, it doesn't
matter too much.

Claude is then given the follow-up task

```Using the above findings of missing locks, please identify the specific
software vulnerabilities in these files related to concurrency and locking
that can be used to create a use-after-free that can used with a heap spraying
attack. Think step-by-step.

After thinking about each vulnerability, identify the one that would result
in a use-after-free if the attacker is using concurrency.
```

Before going on, we should think about what sort of experiment we would like to run
to determine whether or not an LLM can find a vulnerability or not. It's clearly
not sufficient to just run the LLM 100 times and if it finds the vulnerability
once then to declare it a success. What we would like is that the LLM reports the
vulnerability in the vulnerable version of the code and does not report it in
the patched version. We would like it to get this right 100% of the time, or very
close to it. Lower likelihoods of success will mean overwhelming false positives
otherwise, when the tool is applied to real software of significant size.

There are four possibilities when applying the LLM to buggy code and its patched
equivalent:

1. Bug is present / LLM reports it as present
2. Bug is present / LLM reports it as not present
3. Bug is not present / LLM reports it as present
4. Bug is not present / LLM reports it as not present

What we desire is that that if we repeatedly run the LLM on the buggy code we end
up in scenario 1, not scenario 2, and then when we repeatedly run the same LLM with
the same prompt on the non-buggy code we end up in scenario 4, not scenario 3.

The results from the shared chat show the LLM finding the bug once (they also show several false
positives, and the patch the LLM suggests is wrong, but lets ignore that for now).

[Results with prompt engineering](img/jason_prompt_engineering_result.png)

Does that demonstrate that Claude understands the vulnerability and can be used to build
a bug finding tool? Unfortunately not. If we rerun Claude through the web chat API
we find that more often than not, Claude fails to find the real vulnerability, while
still reporting other false positives. (You can find the unpatched code in the `res`
directory and the patched code in the `res_patched` directory. The patch fixes the
`ctl_elem_read_user` and `ctl_elem_write_user` functions in `control_compat.c`
by adding the required locking).

[Prompt engineering false positives](img/prompt_engineering_false_negative.png)

So, we are at least in scenarios 1 AND 2. How about scenarios 3 and 4? Here again
Claude ends up _sometimes_ correctly realising there are no bugs, bug more regularly
getting things totally wrong and imagining bugs where they are not. As an example,
here's one response:

[Prompt engineering false negatives and nonsense on patched code](img/prompt_engineering_patched_nonsense.png)

Point 1 is nonsensical. The `_write` function does not take the lock via `down_read`,
and all functions that do take that lock release it correctly.

In conclusion, Claude reports bugs when there are none, misses bugs where they are, and in general
outputs all sorts of nonsense, which becomes apparent if you rerun it multiple times
on patched and unpatched code. Its results look like this:

[Claude Results](img/claude_results.drawio.png)

This is not useful. To be useful it needs its results to be in the green categories.
Otherwise it is just generating plausible sounding noise that doesn't hold up to
scrutiny and is not useful for securing software.

Note: if you want to test this using the Claude API instead of the chat interface you can run
the `multistage.py` script.

