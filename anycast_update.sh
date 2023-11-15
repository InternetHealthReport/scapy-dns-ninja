curl https://raw.githubusercontent.com/bgptools/anycast-prefixes/master/anycatch-v4-prefixes.txt > v4.txt
curl https://raw.githubusercontent.com/bgptools/anycast-prefixes/master/anycatch-v6-prefixes.txt > v6.txt

cat v4.txt | perl -ple's/\.\d+\/\d+/.1/' > anycast/dests.v4.txt
cat v6.txt | perl -ple's/\:\:\/\d+/::1/' > anycast/dests.v6.txt
