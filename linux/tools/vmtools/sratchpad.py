class SinglePageClassifierOld(Classifier):
    def __init__(self, fitness_threshold_train, fitness_threshold_print):
        super().__init__(fitness_threshold_train, fitness_threshold_print)
        self.pc_mappings_ = None
        self.event_to_file_page_mapping_ = None
        self.event_to_file_page_candidates_ = None

    def collectPrepare_(self, pc_mappings):
        # prepare mapping objects for storing results
        for mapping in pc_mappings:
            mapping["accessed_pfns_events"] = [np.zeros(len(self.events_)) for _ in range(len(mapping["pfns"]))]

    def collectMappingAdd_(self, mapping, pfn_state, event):
        for off in range(len(pfn_state)):
            mapping["accessed_pfns_events"][off][event] += pfn_state[off]

    def getEventClusterFitness(self, pfn_accesses_events, cluster_events):
        # ideas:
        # min score of cluster elements is cluster score
        # if other events triggered randomly this could also come from some other operation
        #   -> general noise -> penality should not be too high if other events triggered less in comparision
        #   -> calculate their influence with rms
        raw_cluster = pfn_accesses_events[cluster_events]
        mask = np.ones(pfn_accesses_events.size, dtype=bool)
        mask[cluster_events] = False
        non_cluster = pfn_accesses_events[mask]

        min_cluster_score = np.min(raw_cluster)
        noise_score = np.sqrt(np.sum(non_cluster ** 2))

        raw_fitness = np.max(min_cluster_score - noise_score, 0)
        return (raw_fitness, raw_fitness / self.samples_)

    def getEventClusterDescriptor(self, cluster_events):
        descriptor = "-".join([str(x) for x in cluster_events])
        return descriptor

    def processMapping(self, mapping, cluster_size):
        for off in range(len(mapping["accessed_pfns_events"])):
            cluster_events = mapping["accessed_pfns_events_argsort"][off][:cluster_size]
            fitness = self.getEventClusterFitness(mapping["accessed_pfns_events"][off], cluster_events)
            if fitness[1] > self.fitness_threshold_train_:
                self.event_to_file_page_candidates_[cluster_events] += 1
                event_cluster_descriptor = self.getEventClusterDescriptor(cluster_events)
                if not (event_cluster_descriptor in self.event_to_file_page_mapping_):
                    self.event_to_file_page_mapping_[event_cluster_descriptor] = []
                self.event_to_file_page_mapping_[event_cluster_descriptor].append({
                    "events": cluster_events.tolist(),
                    "fitness": fitness,
                    "path": mapping["path"], 
                    "file_offset": mapping["file_offset"] + off * mmap.PAGESIZE,
                    "current_pfn": mapping["pfns"][off]
                })
        return

    def train(self):
        # simple idea -> not very powerful (clustering algorithms, ml would be far more powerful)
        # but fits well with event-triggered eviction approach (periodic sampling is anyhow not wanted)
        #   -> we look at the classification problem page-per-page
        #       -> no detection of higher-order patterns!
        #   -> we want to have every event covered
        #   -> pages which accurately classify ONE event are preferred
        #       -> if not every event is covered, we search for (small) clusters
        #   -> continue until all events are covered or cluster search reached max. size 
        self.event_to_file_page_mapping_ = {}
        self.event_to_file_page_candidates_ = np.zeros(len(events))

        # fast path with cluster size 1
        for mapping in self.pc_mappings_:
            # sort events number by score
            mapping["accessed_pfns_events_argsort"] = [np.argsort(-x) for x in mapping["accessed_pfns_events"]]
            self.processMapping(mapping, 1)
        # stop if everything is classified already
        if not all(self.event_to_file_page_candidates_):
            for cluster_size in range(2, len(events) + 1):
                for mapping in self.pc_mappings_:
                    self.processMapping(mapping, cluster_size)
                # stop everything is classified already
                if all(self.event_to_file_page_candidates_):
                    break

        # sort event_to_pfn mappings by fitness
        for array in self.event_to_file_page_mapping_.values():
            array.sort(key=lambda x: x["fitness"], reverse=True)

        results = {
            "event_strings": [e[0] for e in self.events_],
            "raw_data": self.pc_mappings_,
            "event_to_file_page_mapping": self.event_to_file_page_mapping_
        }
        return results

    def printResults(self):
        for event_file_pages in self.event_to_file_page_mapping_.values():
            if len(event_file_pages) > 0 and event_file_pages[0]["fitness"][1] > self.fitness_threshold_print_:
                event_string = ", ".join([self.events_[e][0] for e in event_file_pages[0]["events"]])
                print("Event: {}".format(event_string))
            else:
                continue
            for event_file_page in event_file_pages:
                if event_file_page["fitness"][1] > self.fitness_threshold_print_:
                    print("Fitness: {}, File: {}, Offset: 0x{:x}, Current PFN: 0x{:x}".format(event_file_page["fitness"][1], event_file_page["path"], event_file_page["file_offset"], event_file_page["current_pfn"]))
