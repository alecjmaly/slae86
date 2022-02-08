# Project 3: Egg hunter

- Study about the Egg Hunter shellcode
- Create a working demo of the Egghunter
- Should be configurable for different payloads






A really good blog post by a previous student [H0mbre](https://h0mbre.github.io/SLAE_Egg_Hunter/) does a really great job consolidating information on egg hunters. Of note, he mentions [this paper](http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf) which defines a few techniques for writing an egg hunter. Of note, h0mbre mentions [this paper](http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf) which defines a few techniques for writing an egg hunter. When searching egg hunters online, you will see a lot of examples using the `access()` method check for validating linux pages of memory that are readable and only a few egg hunters using the `sigcheck()` method to check for valid memory without receiving SIGSEGV signal. That said, I did find one example of it's use by [mmquant](https://mmquant.net/egg-hunters-on-linux/#egghunter_example_sigaction). I mention this to point out a few techniques for finding eggs without throwing exceptions from trying to read memory in inaccessable addresses.


 For brevity, I will not regurgitate the detailed information contained in this blog posts but will instead walk through an example of the `access()` egg hutner methodology. I will use the egg `"cd0e" or 0x65643063 (little endian)` as it seems [epi](https://epi052.gitlab.io/notes-to-self/blog/2020-05-18-osce-exam-practice-part-three/#mona-py-egg) has found it to work better than some other eggs such as `"W00T"`. 




Egg: 0x65643063




