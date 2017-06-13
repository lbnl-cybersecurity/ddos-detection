# ddos-detection

## Automated DDoS Detection System
Because the netflow records are sampled, it is not guarantteed that packets belong to both direction of a flow are captured. But again we would like to have a roughly estimate. We collect all the unique "source address" and "destination address" appearing within a unit time interval, and calculate the overlapping percentage. The result (from the first 5min monitoring interval of lbl_mr2 dataset) is shown below:
```
overlap: 452, total_sa: 1839, total_da: 1845.
```
The overlapping percentage is about 24.6%.
We care more of protecting the ESnet from being DDoSed than that attacking traffic originates from ESnet. Then one related question is that what IP ranges belong to ESnet. 

### Simple Volume-based Anomaly Detector
It is not scalable to track the aggregated traffic volume per destination for each destination appearing in a unit time interval. We are more interested in defending us from being DDoSed, than us generating DDoS traffic (under the assumption that our computers are managed by professional people). We are more interested in the IPs which we care for (i.e. from ESnets or Sites). 

--- Make my code more readable: follow the annotation style.---

