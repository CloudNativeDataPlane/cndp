
### Run Playbook

1. Modify the global vars in the all file under group_vars
2. Run the playbook:

```
$ ansible-playbook -i hosts.ini generate_jsonc.yml
```

note: there are quite a few improvements that could be made to the playbook. This
is just a rough and ready way to generate a configuration. For example, right now
the playbook doesn't take the available amount of CPUs into consideration when
setting queues and threads...
