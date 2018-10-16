(ns cljtls.bytes
  (:require [clojure.test :refer :all]))


(defn bytes->num
  [data]
  (reduce bit-or (map-indexed
                   (fn [i x]
                     (bit-shift-left (bit-and x 0x0FF)
                       (* 8 (- (count data) i 1)))) data)))